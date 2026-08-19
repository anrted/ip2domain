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
from .stage3_stream import verify_camera_streams
from .protocols.discovery import run_local_discovery

logger = logging.getLogger(__name__)

# Max IPs with 2GB RAM: use streaming generator + raise limit to 5M
# But materialize target list only after dedup for masscan/asyncio
_MAX_IPS_V2 = int(os.environ.get("IP2DOMAIN_V2_MAX_IPS", "5000000"))

# Stage 2 concurrency (RAM-aware: each probe ~10-30MB, 20 concurrent ≈ 300-600MB)
_DEFAULT_STAGE2_CONCURRENCY = int(os.environ.get("IP2DOMAIN_V2_STAGE2_CONCURRENCY", "20"))

# Active jobs registry (in-memory, shared with router)
_ACTIVE_JOBS: Dict[str, ScanJob] = {}


def get_job(job_id: str) -> Optional[ScanJob]:
    return _ACTIVE_JOBS.get(job_id)


def list_jobs() -> List[ScanJob]:
    return list(_ACTIVE_JOBS.values())


def _parse_targets_streaming(target_str: str, max_ips: int = _MAX_IPS_V2) -> List[str]:
    """Parse target string to IP list with streaming dedup for RAM efficiency."""
    ips = []
    seen = set()
    count = 0
    for line in target_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net.hosts():
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        ips.append(s)
                        count += 1
                        if count >= max_ips:
                            return ips
            elif "-" in line:
                parts = line.split("-", 1)
                start = int(ipaddress.IPv4Address(parts[0].strip()))
                end = int(ipaddress.IPv4Address(parts[1].strip()))
                for ip_int in range(start, end + 1):
                    s = str(ipaddress.IPv4Address(ip_int))
                    if s not in seen:
                        seen.add(s)
                        ips.append(s)
                        count += 1
                        if count >= max_ips:
                            return ips
            else:
                s = str(ipaddress.ip_address(line))
                if s not in seen:
                    seen.add(s)
                    ips.append(s)
                    count += 1
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


async def run_v2_scan_pipeline(
    job_id: str,
    targets_str: str,
    engine: str = "auto",
    masscan_rate: int = 50000,
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

        # ── Stage 1: Port Sweep ────────────────────────────────────────
        job.stage1_status = "running"
        job.stage = "Stage 1: Сканирование портов..."
        job.add_log(f"[Stage 1] Сканирование {len(targets):,} IP (всего в задаче {full_target_count:,})...")

        stage1_start = asyncio.get_event_loop().time()
        completed_s1 = 0
        total_s1 = len(targets)

        def stage1_progress(completed: int, total: int, cur_ip: str, found: int):
            nonlocal completed_s1
            completed_s1 = completed
            job.stage1_scanned = completed
            job.current_ip = cur_ip
            elapsed = max(0.1, asyncio.get_event_loop().time() - stage1_start)
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
                    camera = await asyncio.wait_for(
                        probe_host_v2(ip, open_ports, credentials, protocols=protocols),
                        timeout=10.0,
                    )
                except asyncio.TimeoutError:
                    logger.debug("[v2 Stage2] Host %s probe timed out", ip)
                    camera = None
                except Exception as exc:
                    logger.warning("[v2 Stage2] Error probing %s: %s", ip, exc)
                    camera = None
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
                        job.add_log(
                            f"[Stage 2] ✓ {ip}: {camera.brand or 'Unknown'} {camera.model or ''} "
                            f"| Протоколы: {', '.join(camera.protocols)} "
                            f"| Потоков: {len(camera.streams)}"
                        )
                        # Persist to storage immediately
                        if storage:
                            try:
                                storage.save_v2_result(camera.to_dict())
                            except Exception:
                                pass

        await asyncio.gather(
            *[fingerprint_host(ip, ports) for ip, ports in responsive_hosts],
            return_exceptions=True,
        )

        job.stage2_status = "done"
        job.add_log(f"[Stage 2] Завершено: найдено {len(job.results)} камер")

        if job.is_cancelled():
            job.status = "cancelled"
            return

        # ── Stage 3: Frame Capture ─────────────────────────────────────
        if capture_frames and job.results:
            job.stage3_status = "running"
            job.stage = f"Stage 3: Захват кадров ({len(job.results)} камер)..."
            job.add_log(f"[Stage 3] Захват скриншотов для {len(job.results)} камер...")

            capture_sem = asyncio.Semaphore(3)  # max 3 ffmpeg at once (RAM limit)
            stage3_done = 0

            async def capture_camera(camera: CameraResult):
                nonlocal stage3_done
                if job.is_cancelled():
                    return
                async with capture_sem:
                    try:
                        await asyncio.wait_for(
                            verify_camera_streams(camera, capture_dir, max_streams_to_try=4),
                            timeout=25.0,
                        )
                    except (asyncio.TimeoutError, Exception) as exc:
                        logger.debug("[v2 Stage3] Error verifying streams for %s: %s", camera.ip, exc)
                    stage3_done += 1
                    job.stage3_completed = stage3_done
                    job.progress_pct = 85 + int((stage3_done / max(1, len(job.results))) * 14)
                    # Update persisted result with screenshot
                    if storage:
                        try:
                            storage.save_v2_result(camera.to_dict())
                        except Exception:
                            pass

            await asyncio.gather(
                *[capture_camera(cam) for cam in job.results],
                return_exceptions=True,
            )

            # Filter out cameras that have 0 working streams after verification
            valid_cameras = []
            for cam in job.results:
                if cam.streams and any(s.verified for s in cam.streams):
                    valid_cameras.append(cam)
                    if storage:
                        try:
                            storage.save_v2_result(cam.to_dict())
                        except Exception:
                            pass
                else:
                    if storage:
                        try:
                            storage.delete_v2_result(cam.ip)
                        except Exception:
                            pass

            job.results = valid_cameras
            job.stage3_status = "done"
            verified = len(valid_cameras)
            job.add_log(f"[Stage 3] Завершено: {verified} камер с подтверждённым видео")

        # ── Done ───────────────────────────────────────────────────────
        job.status = "completed"
        job.progress_pct = 100
        job.stage = (
            f"Сканирование завершено: {len(targets):,} IP, "
            f"найдено {len(job.results)} камер"
        )
        job.add_log(
            f"[✓] Готово! Просканировано {len(targets):,} IP, "
            f"обнаружено {len(job.results)} камер за {_format_eta(asyncio.get_event_loop().time() - stage1_start)}"
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
