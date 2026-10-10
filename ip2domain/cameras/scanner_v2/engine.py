"""Camera Scanner v2 — Main pipeline orchestrator.

4-Stage pipeline:
  Stage 0: Passive local discovery (WS-Discovery, SSDP)
  Stage 1: Adaptive port sweep (asyncio / masscan / nmap -sS)
  Stage 2: Multi-protocol fingerprinting (parallel per host)
  Stage 3: Stream verification + frame capture (ffmpeg)
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .models import (
    CameraResult, ScanJob, CAMERA_PORTS_V2, DEFAULT_CREDENTIALS
)
from .stage1_sweep import adaptive_port_sweep, check_tools
from .stage2_proto import probe_host_v2
from .aggregation import merge_host_cameras, universal_observation_to_camera_result
from .stage3_stream import verify_camera_streams
from .protocols.discovery import run_local_discovery
from ip2domain.scanning.runner import run_bounded
from ip2domain.data.geo_city_db import geo_city_db, camera_geo_fields

logger = logging.getLogger(__name__)

# Max IPs with 2GB RAM: use streaming generator + raise limit to 5M
# But materialize target list only after dedup for masscan/asyncio
_MAX_IPS_V2 = int(os.environ.get("IP2DOMAIN_V2_MAX_IPS", "5000000"))

# Stage 2 concurrency (each probe now capped at ≤50s; 50 workers ≈ fine with 2GB RAM)
_DEFAULT_STAGE2_CONCURRENCY = int(os.environ.get("IP2DOMAIN_V2_STAGE2_CONCURRENCY", "50"))

# Active jobs registry (in-memory, shared with router)
_ACTIVE_JOBS: Dict[str, ScanJob] = {}


def get_job(job_id: str) -> Optional[ScanJob]:
    return _ACTIVE_JOBS.get(job_id)


def list_jobs() -> List[ScanJob]:
    return list(_ACTIVE_JOBS.values())


def _parse_targets_streaming(target_str: str, max_ips: int = _MAX_IPS_V2) -> List[str]:
    """Parse target string to IPv4 list with streaming dedup for RAM efficiency."""
    ips = []
    seen = set()
    count = 0
    for line in target_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip comments and handle ranges with spaces like '10.0.0.1 - 10.0.0.3'
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        clean = line.replace(" ", "").split(",")[0].strip()
        if not clean:
            continue
        try:
            if "/" in clean:
                net = ipaddress.ip_network(clean, strict=False)
                if net.version != 4:
                    continue  # Ignore IPv6 networks
                if net.prefixlen < 12:
                    continue  # Safety: ignore excessively large networks
                for ip in net.hosts():
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        ips.append(s)
                        count += 1
                        if count >= max_ips:
                            return ips
            elif "-" in clean:
                parts = clean.split("-", 1)
                start_addr = ipaddress.ip_address(parts[0].strip())
                end_str = parts[1].strip()
                if not "." in end_str and end_str.isdigit():
                    # Handle short notation like 10.0.0.1-255
                    sp = str(start_addr).split(".")
                    end_str = f"{sp[0]}.{sp[1]}.{sp[2]}.{end_str}"
                end_addr = ipaddress.ip_address(end_str)
                if start_addr.version != 4 or end_addr.version != 4:
                    continue  # Ignore IPv6
                start = int(start_addr)
                end = int(end_addr)
                if end < start or (end - start) > 1000000:
                    continue
                for ip_int in range(start, end + 1):
                    s = str(ipaddress.IPv4Address(ip_int))
                    if s not in seen:
                        seen.add(s)
                        ips.append(s)
                        count += 1
                        if count >= max_ips:
                            return ips
            else:
                addr = ipaddress.ip_address(clean.split(":")[0])
                if addr.version != 4:
                    continue
                s = str(addr)
                if s not in seen:
                    seen.add(s)
                    ips.append(s)
                    count += 1
                    if count >= max_ips:
                        return ips
        except Exception:
            continue
    return ips



def _has_private_targets(targets: List[str]) -> bool:
    """Check if any target IP is in a private range (for local discovery)."""
    for ip in targets[:100]:  # sample first 100
        try:
            if ipaddress.ip_address(ip).is_private:
                return True
        except Exception:
            pass
    return False


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "..."
    if seconds < 60:
        return f"{int(seconds)}с"
    if seconds < 3600:
        return f"{int(seconds // 60)}м {int(seconds % 60)}с"
    return f"{int(seconds // 3600)}ч {int((seconds % 3600) // 60)}м"


async def _capture_job_streams(job, capture_dir, storage):
    """Shared capture stage: bounded workers, capturing RTSP frames and Web screenshots."""
    job.stage3_status = "running"
    job.stage = "Stage 3: Захват кадров видео и веб-скриншотов"
    total = sum(len(c.streams) for c in job.results) + len(job.results)
    completed = 0

    async def capture(camera):
        nonlocal completed
        def save_stream(stream):
            nonlocal completed
            completed += 1
            job.stage = f"Stage 3: Захвачено превью {completed}/{total}"
            job.progress_pct = 85 + int(completed / max(1, total) * 14)
            if stream.verified and storage:
                storage.save_v2_result(camera.to_dict())
        try:
            if camera.streams:
                await verify_camera_streams(camera, capture_dir,
                                            is_cancelled=job.is_cancelled, on_stream=save_stream)
        except Exception:
            job.stage3_status = "error"
            raise
        finally:
            from .aggregation import prune_unverified_streams
            prune_unverified_streams(camera)
            completed += 1
            job.stage3_completed += 1
            if storage:
                storage.save_v2_result(camera.to_dict())

        # 2. Web screenshot capture for routers, web devices, media servers, and cameras
        from .models import HTTP_PORTS, HTTPS_PORTS
        from .web_capture import capture_web_screenshot
        from .models import StreamInfo as _SI

        web_port = camera.http_port or next((p for p in camera.open_ports if p in HTTP_PORTS or p in HTTPS_PORTS), 0)
        should_capture_web = (
            web_port > 0 and (
                camera.device_category in ("router", "generic_web", "nas", "server")
                or "flussonic" in (camera.brand or "").lower()
                or not any(s.verified for s in camera.streams)
            )
        )

        if should_capture_web:
            scheme = "https" if web_port in HTTPS_PORTS or "443" in str(web_port) else "http"
            web_url = camera.web_url or f"{scheme}://{camera.ip}:{web_port}/"
            camera.web_url = web_url
            camera.http_port = camera.http_port or web_port
            try:
                sc_url = await capture_web_screenshot(
                    ip=camera.ip,
                    port=web_port,
                    web_url=web_url,
                    capture_dir=Path(capture_dir),
                    brand=camera.brand,
                    model=camera.model,
                    title=camera.web_title,
                    category=camera.device_category,
                )
                if sc_url:
                    camera.web_screenshot = sc_url
                    if not camera.streams or camera.device_category in ("router", "generic_web", "server") or "flussonic" in (camera.brand or "").lower():
                        camera.streams.insert(0, _SI(
                            url=web_url,
                            stream_type="web_panel",
                            verified=True,
                            screenshot_path=str(Path(capture_dir) / Path(sc_url).name),
                        ))
                    if storage:
                        storage.save_v2_result(camera.to_dict())
            except Exception as exc:
                logger.debug("[Stage 3] Web screenshot error on %s: %s", camera.ip, exc)

    await run_bounded(job.results, capture, 3, job.is_cancelled)
    job.stage3_status = "cancelled" if job.is_cancelled() else "done"


async def _resolve_job_geo(job, storage):
    job.stage4_status = "running"
    for cam in job.results:
        if job.is_cancelled():
            break
        geo = await asyncio.to_thread(geo_city_db.find_by_ip, cam.ip)
        fields = camera_geo_fields(geo or {})
        for key, value in fields.items():
            setattr(cam, key, value)
        if storage:
            storage.update_v2_geo(cam.ip, fields)
        job.stage4_completed += 1
    job.stage4_status = "cancelled" if job.is_cancelled() else "done"


async def run_v2_scan_pipeline(
    job_id: str,
    targets_str: str,
    engine: str = "auto",
    masscan_rate: int = 25000,
    concurrency: int = 150,
    port_timeout: float = 1.2,
    stage2_concurrency: int = _DEFAULT_STAGE2_CONCURRENCY,
    credentials: Optional[List[Tuple[str, str]]] = None,
    protocols: Optional[List[str]] = None,
    capture_frames: bool = True,
    local_discovery: bool = True,
    capture_dir: Optional[Path] = None,
    storage=None,
    resume_from_index: int = 0,
) -> None:
    """Main v2 scan pipeline with auto-resume support. Runs in background asyncio task."""
    job = _ACTIVE_JOBS.get(job_id)
    if not job:
        logger.error("[v2 Engine] Job %s not found in _ACTIVE_JOBS", job_id)
        return

    if capture_dir is None:
        capture_dir = Path(__file__).resolve().parent.parent.parent / "web" / "v2_captures"
    capture_dir.mkdir(parents=True, exist_ok=True)

    if credentials is None:
        credentials = DEFAULT_CREDENTIALS

    ts = lambda: datetime.now().strftime("%H:%M:%S")

    try:
        if stage2_concurrency < 1:
            raise ValueError("stage2_concurrency must be positive")
        job.status = "running"
        job.stage = "Подготовка..."
        if resume_from_index > 0:
            job.add_log(f"[Возобновление] Продолжение сканирования с IP #{resume_from_index + 1:,}")
        else:
            job.add_log("Запуск Camera Scanner v2...")

        # ── Parse targets ──────────────────────────────────────────────
        job.add_log(f"Разбор целей (лимит: {_MAX_IPS_V2:,} IP)...")
        targets = _parse_targets_streaming(targets_str)
        job.total_targets = len(targets)
        job.add_log(f"Целей для сканирования: {len(targets):,} IP")

        if not targets:
            job.status = "completed"
            job.stage = "Нет корректных целей"
            job.progress_pct = 100
            if storage:
                storage.save_v2_job(job.to_dict())
            return

        # Persist initial job record to DB for restart survival
        if storage:
            try:
                storage.save_v2_job({
                    "job_id": job_id,
                    "status": "running",
                    "targets_str": targets_str,
                    "current_index": resume_from_index,
                    "params": {
                        "engine": engine,
                        "masscan_rate": masscan_rate,
                        "concurrency": concurrency,
                        "port_timeout": port_timeout,
                        "stage2_concurrency": stage2_concurrency,
                        "credentials": credentials,
                        "protocols": protocols,
                        "capture_frames": capture_frames,
                        "local_discovery": local_discovery,
                    },
                    "total_targets": len(targets),
                    "results_count": len(job.results),
                    "engine_used": engine,
                    "progress_pct": job.progress_pct,
                    "stage": job.stage,
                    "logs": job.logs,
                })
            except Exception as e:
                logger.debug("[v2 Engine] Initial save_v2_job error: %s", e)

        # ── Stage 0: Local Discovery (only if starting from beginning) ──
        discovered_ips = []
        if resume_from_index == 0 and local_discovery and _has_private_targets(targets):
            job.stage0_status = "running"
            job.stage = "Stage 0: LAN Discovery (WS-Discovery, SSDP)..."
            job.add_log("[Stage 0] Запуск мультикаст-обнаружения...")
            try:
                discovered_ips = await asyncio.wait_for(run_local_discovery(), timeout=8.0)
                job.stage0_found = len(discovered_ips)
                job.add_log(f"[Stage 0] Обнаружено через mDNS/SSDP: {len(discovered_ips)} камер")
                # Add discovered IPs to front of target list (skip duplicates)
                existing = set(targets)
                for ip in discovered_ips:
                    if ip not in existing:
                        targets.insert(0, ip)
                        existing.add(ip)
                job.total_targets = len(targets)
            except Exception as exc:
                job.add_log(f"[Stage 0] Ошибка: {exc}")
            job.stage0_status = "done"
        else:
            job.stage0_status = "skipped"

        if job.is_cancelled():
            job.status = "cancelled"
            if storage:
                storage.mark_v2_job_status(job_id, "cancelled")
            return

        # Slice remaining targets if resuming
        full_target_count = len(targets)
        if resume_from_index > 0:
            if resume_from_index < len(targets):
                targets = targets[resume_from_index:]
            else:
                targets = []

        job.progress_pct = 5

        # ── Scanner v2 Staged Engine Execution Branch ──────────────────
        if engine == "staged":
            job.engine_used = "staged"
            job.stage = "Scanner v2 Staged Pipeline: запуск..."
            job.add_log("[Scanner v2 Staged] Запуск через staged_pipeline (discover -> identify -> enrich)...")
            try:
                from ip2domain.scanning.policies import ScanConfig
                from ip2domain.scanning.persistence import InventoryRepository
                from ip2domain.scanning.staged_pipeline import run_staged_scan
                from ip2domain.cameras.scanner_v2.aggregation import universal_observation_to_camera_result

                inv_db_path = (
                    os.environ.get("IP2DOMAIN_INVENTORY_DB_PATH", getattr(storage, "db_path", "ip2domain.db") + ".inventory")
                    if storage else "ip2domain.db.inventory"
                )
                repo = InventoryRepository(inv_db_path)
                scan_cfg = ScanConfig(
                    targets=targets_str,
                    profile="camera_legacy",
                    workers=min(max(stage2_concurrency, 4), 32),
                    discovery_workers=min(max(concurrency // 15, 2), 16),
                    web_enrichment=True,
                    active_consent=True,
                )
                plan = scan_cfg.plan()
                scan_id = repo.create(scan_cfg, plan)

                async def _poll_staged_job():
                    while not job.is_cancelled():
                        await asyncio.sleep(3.0)
                        try:
                            st = await asyncio.to_thread(repo.get, scan_id)
                        except Exception:
                            continue
                        if not st:
                            continue
                        cov = st.get("coverage", {})
                        done_bl = st.get("completed_blocks", 0)
                        tot_bl = max(1, st.get("total_blocks", 1))
                        pct = int((done_bl / tot_bl) * 85)
                        job.progress_pct = max(5, min(90, pct))
                        open_cnt = cov.get("state:open", 0)
                        id_cnt = cov.get("identified", 0)
                        job.stage = f"Scanner v2 Staged: {done_bl}/{tot_bl} блоков · Открыто: {open_cnt} · Опознано: {id_cnt}"
                        if st.get("status") in ("completed", "cancelled", "error"):
                            break

                poll_task = asyncio.create_task(_poll_staged_job())
                try:
                    await run_staged_scan(repo, scan_id)
                finally:
                    poll_task.cancel()
                    await asyncio.gather(poll_task, return_exceptions=True)

                # Page through every endpoint; aggregate before any IP-keyed save.
                hosts = {}
                offset = 0
                while not job.is_cancelled():
                    eps = await asyncio.to_thread(repo.endpoints, scan_id, limit=1000, offset=offset)
                    if not eps:
                        break
                    for ep in eps:
                        cam = universal_observation_to_camera_result(ep)
                        if cam:
                            hosts.setdefault(cam.ip, []).append(cam)
                    offset += len(eps)
                job.results = [merge_host_cameras(parts) for parts in hosts.values()]
                for cam in job.results:
                    if storage:
                        storage.save_v2_result(cam.to_dict())
                scan_state = (await asyncio.to_thread(repo.get, scan_id)) or {}
                if scan_state.get("status") == "error":
                    raise RuntimeError("Staged scan failed")
                if scan_state.get("status") == "cancelled":
                    job.cancelled = True

                job.add_log(f"[Scanner v2 Staged] Завершено. Обнаружено камер/видеопотоков: {len(job.results)}")
            except Exception as exc:
                logger.exception("[Scanner v2 Staged] Ошибка выполнения: %s", exc)
                job.add_log(f"[Scanner v2 Staged] Ошибка: {exc}")
                raise

            # Optional frame verification & capture
            if capture_frames and job.results and not job.is_cancelled():
                job.stage = "Stage 3: Захват превью камер..."
                job.add_log("[Stage 3] Запуск захвата скриншотов ffmpeg...")
                await _capture_job_streams(job, capture_dir, storage)
            else:
                job.stage3_status = "skipped"
            if job.is_cancelled():
                job.status = "cancelled"
                if storage:
                    storage.mark_v2_job_status(job.job_id, "cancelled")
                return

            await _resolve_job_geo(job, storage)
            if job.is_cancelled():
                job.status = "cancelled"
                if storage:
                    storage.mark_v2_job_status(job.job_id, "cancelled")
                return
            job.progress_pct = 100
            job.status = "completed"
            job.stage = f"Завершено: найдено {len(job.results)} камер"
            if storage:
                storage.save_v2_job(job.to_dict())
            return

        # ── Stage 1: Port Sweep ────────────────────────────────────────
        job.stage1_status = "running"
        tools = check_tools()
        chosen_engine = engine
        if chosen_engine == "auto":
            chosen_engine = (
                "masscan"
                if (len(targets) >= 4096 and tools["masscan"] and tools["is_root"])
                else ("nmap_syn" if (len(targets) >= 4096 and tools["nmap"] and tools["is_root"]) else "asyncio")
            )
        job.engine_used = chosen_engine
        if chosen_engine == "masscan":
            engine_desc = f"masscan ({masscan_rate:,} pps, 48 портов)"
        elif chosen_engine == "nmap_syn":
            engine_desc = "nmap -sS SYN"
        else:
            engine_desc = f"asyncio TCP (параллельность: {concurrency})"

        job.stage = f"Stage 1: Сканирование портов ({chosen_engine})..."
        job.add_log(f"[Stage 1] Запуск {engine_desc} для {len(targets):,} IP (всего в задаче {full_target_count:,})...")

        stage1_start = asyncio.get_event_loop().time()
        completed_s1 = 0
        total_s1 = len(targets)
        last_log_time = 0.0

        def stage1_progress(completed: int, total: int, cur_ip: str, found: int):
            nonlocal completed_s1, last_log_time
            completed_s1 = completed
            job.stage1_scanned = completed
            elapsed = max(0.1, asyncio.get_event_loop().time() - stage1_start)

            if "rate:" in cur_ip and "%" in cur_ip:
                # Direct masscan status line (e.g. "rate: 49.90-kpps, 1.23% done, 0:45:12 remaining, found=15")
                job.current_ip = ""
                job.stage = f"Stage 1: masscan [{resume_from_index + completed:,}/{full_target_count:,}] · {cur_ip}"
                pct_num = min(100.0, (completed / max(1, total)) * 100)
                job.progress_pct = 5 + int(pct_num * 0.35)
                # Log progress periodically (every 30s)
                now = asyncio.get_event_loop().time()
                if now - last_log_time >= 30.0:
                    last_log_time = now
                    job.add_log(f"[Stage 1/masscan] {cur_ip}")
            else:
                job.current_ip = cur_ip
                speed = completed / elapsed if completed > 0 else 0
                eta = (total - completed) / speed if speed > 0 else 0
                job.progress_pct = 5 + int((completed / max(1, total)) * 35)
                job.stage = (
                    f"Stage 1: Sweep [{resume_from_index + completed:,}/{full_target_count:,}] "
                    f"· {speed:.0f} IP/сек · ост. {_format_eta(eta)}"
                )

            # Periodically persist index to DB for restart recovery
            if storage and (completed % 100 == 0 or completed == total):
                try:
                    storage.update_v2_job_progress(
                        job_id=job_id,
                        current_index=resume_from_index + completed,
                        progress_pct=job.progress_pct,
                        stage=job.stage,
                        found_cameras=len(job.results),
                        logs=job.logs,
                    )
                except Exception:
                    pass

        responsive_hosts, engine_used = await adaptive_port_sweep(
            targets=targets,
            ports=CAMERA_PORTS_V2,
            engine=engine,
            masscan_rate=masscan_rate,
            concurrency=concurrency,
            port_timeout=port_timeout,
            on_progress=stage1_progress,
            is_cancelled=job.is_cancelled,
        )


        job.engine_used = engine_used
        job.stage1_responsive = len(responsive_hosts)
        job.stage1_status = "done"
        job.add_log(
            f"[Stage 1] Завершено ({engine_used}): {len(targets):,} IP просканировано, "
            f"{len(responsive_hosts)} активных хостов с открытыми портами"
        )

        if job.is_cancelled():
            job.status = "cancelled"
            return

        if not responsive_hosts:
            job.status = "completed"
            job.progress_pct = 100
            job.stage = f"Завершено: {len(targets):,} IP, активных камер не найдено"
            return

        # ── Stage 2: Fingerprinting ────────────────────────────────────
        job.stage2_status = "running"
        job.stage2_total = len(responsive_hosts)
        job.stage = f"Stage 2: Идентификация {len(responsive_hosts)} хостов..."
        job.add_log(f"[Stage 2] Запуск мультипротокольного анализа {len(responsive_hosts)} хостов...")

        semaphore2 = asyncio.Semaphore(stage2_concurrency)
        stage2_done = 0
        stage2_lock = asyncio.Lock()
        stage2_start = asyncio.get_event_loop().time()

        async def fingerprint_host(ip: str, open_ports: List[int]):
            nonlocal stage2_done
            if job.is_cancelled():
                return
            async with semaphore2:
                if job.is_cancelled():
                    return
                try:
                    camera = await probe_host_v2(ip, open_ports, credentials, protocols=protocols)
                except asyncio.TimeoutError:
                    logger.debug("[v2 Stage2] Host %s probe timed out, checking open ports fallback", ip)
                    camera = None
                    cctv_ports = [p for p in open_ports if p in {554, 555, 5555, 8554, 34567, 34599, 37777}]
                    if cctv_ports:
                        p = cctv_ports[0]
                        from .models import StreamInfo as _SI2
                        if p in {34567, 34599}:
                            camera = CameraResult(ip=ip, brand="Xiongmai", model="NETSurveillance Device", rtsp_port=554, auth_required=None, open_ports=sorted(open_ports), protocols=["xiongmai_sofia"])
                            camera.streams.append(_SI2(url=f"rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0", stream_type="rtsp", auth_required=None))
                        elif p == 37777:
                            camera = CameraResult(ip=ip, brand="Dahua", model="Dahua DVR/NVR", rtsp_port=554, auth_required=None, open_ports=sorted(open_ports), protocols=["dahua_dhip"])
                            camera.streams.append(_SI2(url=f"rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0", stream_type="rtsp", auth_required=None))
                        else:
                            camera = CameraResult(ip=ip, brand="Generic RTSP", rtsp_port=p, auth_required=None, open_ports=sorted(open_ports), protocols=["rtsp_direct"])
                            camera.streams.append(_SI2(url=f"rtsp://{ip}:{p}/live/ch0", stream_type="rtsp", auth_required=None))
                            camera.streams.append(_SI2(url=f"rtsp://{ip}:{p}/Streaming/Channels/101", stream_type="rtsp", auth_required=None))
                except Exception as exc:
                    logger.warning("[v2 Stage2] Error probing %s: %s", ip, exc)
                    camera = None

                if not camera and open_ports:
                    from .models import HTTP_PORTS as _HTTP_PORTS
                    if 8291 in open_ports:
                        camera = CameraResult(
                            ip=ip, brand="MikroTik", model="RouterOS",
                            device_category="router", open_ports=sorted(open_ports),
                            protocols=["winbox"]
                        )
                    elif any(p in _HTTP_PORTS for p in open_ports):
                        hp = next(p for p in open_ports if p in _HTTP_PORTS)
                        camera = CameraResult(
                            ip=ip, brand="Generic Web Device", model="Web Service",
                            http_port=hp, web_url=f"http://{ip}:{hp}/",
                            device_category="generic_web", open_ports=sorted(open_ports),
                            protocols=["http"]
                        )
                    else:
                        camera = CameraResult(
                            ip=ip, brand="Generic Network Device",
                            device_category="device", open_ports=sorted(open_ports),
                            protocols=["tcp"]
                        )

                async with stage2_lock:
                    stage2_done += 1
                    job.stage2_completed = stage2_done
                    job.current_ip = ip
                    elapsed = max(0.1, asyncio.get_event_loop().time() - stage2_start)
                    speed = stage2_done / elapsed
                    eta = (job.stage2_total - stage2_done) / speed if speed > 0 else 0
                    job.progress_pct = 40 + int((stage2_done / max(1, job.stage2_total)) * 45)
                    job.stage = (
                        f"Stage 2: [{stage2_done}/{job.stage2_total}] {ip} "
                        f"· найдено {len(job.results)} · ост. {_format_eta(eta)}"
                    )
                    if camera:
                        from datetime import datetime as _dt
                        camera.timestamp = _dt.now().isoformat()
                        job.results.append(camera)
                        cat_tag = f"[{camera.device_category.upper()}] " if getattr(camera, "device_category", "camera") != "camera" else ""
                        job.add_log(
                            f"[Stage 2] ✓ {ip}: {cat_tag}{camera.brand or 'Unknown'} {camera.model or ''} "
                            f"| Порты: {camera.open_ports} | Протоколы: {', '.join(camera.protocols) or 'tcp'}"
                        )
                        # Persist to storage immediately
                        if storage:
                            try:
                                storage.save_v2_result(camera.to_dict())
                            except Exception:
                                pass

        async def fingerprint_target(target):
            await fingerprint_host(*target)

        await run_bounded(
            responsive_hosts, fingerprint_target, stage2_concurrency, job.is_cancelled,
        )

        job.stage2_status = "done"
        job.add_log(f"[Stage 2] Завершено: найдено {len(job.results)} камер")

        if job.is_cancelled():
            job.status = "cancelled"
            return

        # ── Stage 3: Frame Capture ─────────────────────────────────────
        if capture_frames and job.results:
            await _capture_job_streams(job, capture_dir, storage)
            if job.is_cancelled():
                job.status = "cancelled"
                return

            # Keep identified endpoints even when they expose no media yet.
            # Cameras where ffmpeg capture failed are kept but marked — they still have RTSP URLs
            # which can be checked manually or via the preview proxy.
            valid_cameras = []
            verified_count = 0
            for cam in job.results:
                from .aggregation import prune_unverified_streams
                prune_unverified_streams(cam)
                has_verified = any(s.verified for s in cam.streams) or bool(cam.web_screenshot)
                if has_verified:
                    verified_count += 1
                valid_cameras.append(cam)
                if storage:
                    try:
                        storage.save_v2_result(cam.to_dict())
                    except Exception:
                        pass

            job.results = valid_cameras
            job.found_cameras = len(valid_cameras)
            job.stage3_status = "done"
            job.add_log(
                f"[Stage 3] Завершено: {len(valid_cameras)} устройств сохранено "
                f"({verified_count} со скриншотом/видео, {len(valid_cameras) - verified_count} без скриншота)"
            )

        # Geolocation is independent of frame availability.
        await _resolve_job_geo(job, storage)
        if job.is_cancelled():
            job.status = "cancelled"
            return

        # ── Done ───────────────────────────────────────────────────────
        job.status = "completed"
        job.progress_pct = 100
        job.stage = (
            f"Сканирование завершено: {len(targets):,} IP, "
            f"найдено {len(job.results)} устройств"
        )

        job.add_log(
            f"[✓] Готово! Просканировано {len(targets):,} IP, "
            f"обнаружено {len(job.results)} устройств за {_format_eta(asyncio.get_event_loop().time() - stage1_start)}"
        )
        if storage:
            try:
                storage.save_v2_job(job.to_dict())
            except Exception:
                pass

    except asyncio.CancelledError:
        job.status = "cancelled"
        job.stage = "Сканирование отменено"
        if storage:
            try:
                storage.mark_v2_job_status(job_id, "cancelled")
            except Exception:
                pass
    except Exception as exc:
        logger.exception("[v2 Engine] Unhandled error in job %s", job_id)
        job.status = "error"
        job.error = str(exc)
        job.stage = f"Ошибка: {exc}"
        if storage:
            try:
                storage.save_v2_job(job.to_dict())
            except Exception:
                pass
    finally:
        pass


def create_job(job_id: str) -> ScanJob:
    """Create and register a new ScanJob."""
    job = ScanJob(job_id=job_id)
    _ACTIVE_JOBS[job_id] = job
    return job


def cancel_job(job_id: str) -> bool:
    """Request cancellation of a running job."""
    job = _ACTIVE_JOBS.get(job_id)
    if job:
        job.cancelling = True
        return True
    return False
