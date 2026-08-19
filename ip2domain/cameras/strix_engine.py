"""Modular 2-Stage Strix Scanning Engine.

Stage 1: Ultra-fast asynchronous non-blocking TCP port sweep (200-300 concurrency).
Stage 2: Targeted deep video stream testing via Strix for hosts with confirmed open camera ports.
"""

import asyncio
import hashlib
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import httpx

from ip2domain.core.storage import StorageManager

logger = logging.getLogger(__name__)

STRIX_API_URL = os.environ.get("STRIX_API_URL", "http://127.0.0.1:4567")
_ENGINE_DIR = Path(__file__).resolve().parents[1]
STRIX_CAPTURE_DIR = _ENGINE_DIR / "web" / "strix_captures"
STRIX_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
_FFMPEG_SEMAPHORE = asyncio.Semaphore(max(1, min(6, int(os.environ.get("IP2DOMAIN_STRIX_FFMPEG_CONCURRENCY", "3")))))

# Standard comprehensive ports for IP cameras, DVRs, NVRs, and RTSP/HTTP endpoints (prioritized)
DEFAULT_CAMERA_PORTS: Tuple[int, ...] = (
    554, 80, 8080, 8000, 37777, 8899, 8090, 8008, 555, 8443, 81, 88,
    10554, 5544, 8001, 1935, 1026, 7070, 85, 4747, 8082, 8083, 2600,
    6554, 99, 10001, 8081
)


async def check_single_port(ip: str, port: int, timeout: float = 1.5) -> int:
    """Non-blocking TCP handshake check for an individual IP port."""
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return port
    except Exception:
        return 0
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def probe_ip_ports(ip: str, ports: Tuple[int, ...] = DEFAULT_CAMERA_PORTS, timeout: float = 1.5) -> List[int]:
    """Check all target camera ports for a given IP in parallel."""
    tasks = [check_single_port(ip, p, timeout=timeout) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [p for p in results if isinstance(p, int) and p > 0]


async def fast_port_sweep(
    targets: List[str],
    ports: Optional[Tuple[int, ...]] = None,
    concurrency: int = 25,
    timeout: float = 1.5,
    on_progress: Optional[Callable[[int, int, str, int], None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> List[Tuple[str, List[int]]]:
    """Execute reliable high-speed Stage 1 port sweep across targets.

    Uses a controlled host concurrency (25-35) so the OS socket queue is not flooded with SYN packets.
    Returns: List of tuples (ip, [open_ports]) for responsive hosts only.
    """
    check_ports = ports or DEFAULT_CAMERA_PORTS
    concurrency = max(10, min(60, int(concurrency or 25)))
    semaphore = asyncio.Semaphore(concurrency)
    discovered: List[Tuple[str, List[int]]] = []
    completed = 0
    total = len(targets)
    lock = asyncio.Lock()

    async def worker(ip: str):
        nonlocal completed
        if is_cancelled and is_cancelled():
            return
        async with semaphore:
            if is_cancelled and is_cancelled():
                return
            open_ports = await probe_ip_ports(ip, ports=check_ports, timeout=timeout)
            async with lock:
                completed += 1
                if open_ports:
                    discovered.append((ip, open_ports))
                if on_progress:
                    on_progress(completed, total, ip, len(discovered))

    batch_size = 500
    for b_start in range(0, total, batch_size):
        if is_cancelled and is_cancelled():
            break
        batch = targets[b_start : b_start + batch_size]
        tasks = [asyncio.create_task(worker(ip)) for ip in batch]
        await asyncio.gather(*tasks, return_exceptions=True)

    return discovered


async def extract_stream_frame(stream_url: str, output_file: Path) -> bool:
    """Capture a single frame from an RTSP/HTTP camera stream using ffmpeg."""
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg or not stream_url:
        return False
    temp_file = output_file.with_suffix(".tmp.jpg")
    try:
        temp_file.unlink(missing_ok=True)
        async with _FFMPEG_SEMAPHORE:
            cmd = [
                ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                "-rtsp_transport", "tcp",
                "-timeout", "6000000",
                "-i", stream_url,
                "-frames:v", "1",
                "-vf", "scale=min(960\\,iw):-2",
                "-q:v", "4",
                "-update", "1",
                str(temp_file),
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(process.communicate(), timeout=8.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                temp_file.unlink(missing_ok=True)
                return False

        if process.returncode == 0 and temp_file.is_file() and temp_file.stat().st_size > 0:
            temp_file.replace(output_file)
            return True
        temp_file.unlink(missing_ok=True)
        return False
    except Exception:
        temp_file.unlink(missing_ok=True)
        return False


def _format_eta(seconds: float) -> str:
    if seconds < 0 or seconds > 86400 * 7:
        return "..."
    sec = int(seconds)
    if sec < 60:
        return f"~{sec}с"
    mins = sec // 60
    rem_sec = sec % 60
    if mins < 60:
        return f"~{mins}м {rem_sec}с"
    hrs = mins // 60
    rem_mins = mins % 60
    if hrs < 24:
        return f"~{hrs}ч {rem_mins}м"
    days = hrs // 24
    rem_hrs = hrs % 24
    return f"~{days}д {rem_hrs}ч"
def _is_valid_image_bytes(content: Optional[bytes]) -> bool:
    """Verify that payload contains actual binary image data (JPEG/PNG/WebP), not HTML error pages."""
    if not content or len(content) < 300:
        return False
    if content.startswith(b"\xff\xd8\xff"):  # JPEG
        return True
    if content.startswith(b"\x89PNG\r\n\x1a\n"):  # PNG
        return True
    if len(content) > 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":  # WebP
        return True
    return False


async def _download_strix_screenshot(client: httpx.AsyncClient, session_id: str, stream_idx: int, sc_path: str) -> Optional[bytes]:
    """Download and validate screenshot from Strix."""
    if sc_path and session_id:
        target_url = f"{STRIX_API_URL}/{sc_path.lstrip('/')}"
        try:
            resp = await client.get(target_url, timeout=4.0)
            if resp.status_code == 200 and _is_valid_image_bytes(resp.content):
                return resp.content
        except Exception:
            pass

    if session_id:
        try:
            resp = await client.get(f"{STRIX_API_URL}/api/test/screenshot", params={"id": session_id, "i": stream_idx}, timeout=3.0)
            if resp.status_code == 200 and _is_valid_image_bytes(resp.content):
                return resp.content
        except Exception:
            pass
    return None


async def run_strix_scan_pipeline(
    job_id: str,
    targets: List[str],
    ids: str,
    user: str,
    password: str,
    channel: str,
    ports: str,
    skip_existing: bool = False,
    concurrency: int = 10,
    start_index: int = 0,
    strict_video_only: bool = True,
    storage: Optional[StorageManager] = None,
    strix_jobs_dict: Optional[Dict[str, Any]] = None,
    results_cache: Optional[List[dict]] = None,
):
    """Orchestrate the 2-Stage Strix Discovery Pipeline.

    Stage 1: High-concurrency port filter (200-300 workers) -> fast discard of closed IPs.
    Stage 2: Strix deep stream probe with low concurrency (1-2 workers) on responsive hosts.
    """
    if storage is None:
        storage = StorageManager()
    if strix_jobs_dict is None:
        try:
            from ip2domain.web.routers.common import strix_jobs
            strix_jobs_dict = strix_jobs
        except Exception:
            strix_jobs_dict = {}
    if results_cache is None:
        try:
            from ip2domain.web.routers.common import strix_results_cache
            results_cache = strix_results_cache
        except Exception:
            results_cache = []

    job = strix_jobs_dict.get(job_id)
    if not job:
        db_job = storage.get_strix_job(job_id)
        if db_job:
            job = {
                "job_id": job_id,
                "status": "running",
                "total_targets": len(targets),
                "current_index": start_index,
                "current_ip": "",
                "progress_pct": 0,
                "stage": "Возобновление сканирования...",
                "results": [],
                "logs": db_job.get("logs", []),
                "active_session_id": None,
                "cancelling": False,
                "cancelled": False,
            }
            strix_jobs_dict[job_id] = job
        else:
            return

    job["status"] = "running"
    job["total_targets"] = len(targets)

    def is_cancelled() -> bool:
        return bool(job.get("cancelling") or job.get("cancelled"))

    saved_ips: Set[str] = set()
    if skip_existing:
        try:
            db_res = storage.get_strix_results()
            saved_ips = {r["ip"] for r in db_res if r.get("ip")}
        except Exception:
            saved_ips = set()

    active_targets = [ip for ip in targets if not (skip_existing and ip in saved_ips)]
    if not active_targets:
        job["status"] = "completed"
        job["progress_pct"] = 100
        job["stage"] = "Все цели уже были сохранены ранее"
        try:
            storage.update_strix_job_progress(job_id, len(targets), "", 100, job["stage"], status="completed", logs=job["logs"])
        except Exception:
            pass
        return

    # ── STAGE 1: Fast Port Sweep ───────────────────────────────────────
    stage1_log = f"[{datetime.now().strftime('%H:%M:%S')}] Этап 1/2: Запуск высокоскоростного сканирования портов ({len(active_targets)} IP)..."
    job["logs"].append(stage1_log)
    job["stage"] = f"Этап 1/2: Проверка открытых портов (0/{len(active_targets)} IP)..."

    parsed_ports = None
    if ports:
        try:
            parsed_ports = tuple(int(p.strip()) for p in ports.split(",") if p.strip().isdigit())
        except Exception:
            parsed_ports = None

    last_update_t = 0.0
    stage1_start_t = asyncio.get_event_loop().time()

    def stage1_progress(completed: int, total: int, cur_ip: str, found_count: int):
        nonlocal last_update_t
        if is_cancelled():
            return
        now = asyncio.get_event_loop().time()
        job["current_ip"] = cur_ip
        # Stage 1 accounts for 0% - 40% of total progress
        pct = round((completed / total) * 40)
        job["progress_pct"] = pct
        elapsed = max(0.1, now - stage1_start_t)
        speed = completed / elapsed
        eta_sec = (total - completed) / max(0.1, speed)
        eta_str = _format_eta(eta_sec)
        job["stage"] = f"Этап 1/2: Проверка портов [{completed}/{total}] · найдено {found_count} камер ({speed:.1f} IP/сек, ост. {eta_str})"
        if now - last_update_t > 2.0:
            last_update_t = now
            try:
                storage.update_strix_job_progress(job_id, completed, cur_ip, pct, job["stage"], status="running", logs=job["logs"])
            except Exception:
                pass

    # Scale port scanning concurrency based on user concurrency (default 25 workers)
    stage1_concurrency = max(10, min(50, int(concurrency or 25)))
    port_timeout = float(os.environ.get("IP2DOMAIN_STRIX_PORT_TIMEOUT", "1.5"))
    responsive_hosts = await fast_port_sweep(
        active_targets,
        ports=parsed_ports,
        concurrency=stage1_concurrency,
        timeout=port_timeout,
        on_progress=stage1_progress,
        is_cancelled=is_cancelled,
    )

    if is_cancelled():
        job["status"] = "cancelled"
        job["stage"] = "Сканирование прервано пользователем"
        try:
            storage.update_strix_job_progress(job_id, 0, "", job["progress_pct"], job["stage"], status="cancelled", logs=job["logs"])
        except Exception:
            pass
        return

    stage1_done_log = f"[{datetime.now().strftime('%H:%M:%S')}] Этап 1/2 завершен: проверено {len(active_targets)} IP, найдено {len(responsive_hosts)} активных хостов с открытыми портами"
    job["logs"].append(stage1_done_log)

    if not responsive_hosts:
        job["status"] = "completed"
        job["progress_pct"] = 100
        job["stage"] = f"Сканирование завершено: проверено {len(targets)} IP, активных камер не найдено"
        _save_completed_cidrs(storage, job_id, len(targets), 0)
        try:
            storage.update_strix_job_progress(job_id, len(targets), "", 100, job["stage"], status="completed", logs=job["logs"])
        except Exception:
            pass
        return

    # ── STAGE 2: Deep Strix Stream Probing ──────────────────────────────
    job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Этап 2/2: Запуск глубокого анализа видеопотоков Strix ({len(responsive_hosts)} хостов)...")

    deep_concurrency = max(1, min(3, int(os.environ.get("IP2DOMAIN_STRIX_DEEP_CONCURRENCY", "1"))))
    strix_semaphore = asyncio.Semaphore(deep_concurrency)
    stage2_completed = 0
    total_stage2 = len(responsive_hosts)
    lock = asyncio.Lock()
    stage2_start_t = asyncio.get_event_loop().time()

    async def probe_strix_host(client: httpx.AsyncClient, ip: str, open_ports: List[int], idx: int):
        nonlocal stage2_completed, last_update_t
        if is_cancelled():
            return

        async with strix_semaphore:
            if is_cancelled():
                return

            async with lock:
                job["current_ip"] = ip
                # Stage 2 accounts for 40% - 100% of total progress
                pct = 40 + round((stage2_completed / max(1, total_stage2)) * 60)
                job["progress_pct"] = min(99, pct)
                now_t = asyncio.get_event_loop().time()
                elapsed2 = max(0.1, now_t - stage2_start_t)
                speed2 = (stage2_completed / elapsed2) * 60 if stage2_completed > 0 else 0
                eta2_sec = (total_stage2 - stage2_completed) / max(0.0001, (stage2_completed / elapsed2)) if stage2_completed > 0 else 0
                eta2_str = _format_eta(eta2_sec) if stage2_completed > 0 else "..."
                speed_str = f" · {speed2:.1f} хост/мин" if speed2 > 0 else ""
                job["stage"] = f"Этап 2/2: Анализ Strix [{stage2_completed+1}/{total_stage2}] {ip} (найдено камер: {len(job['results'])}{speed_str}, ост. {eta2_str})"
                job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Порты {', '.join(map(str, open_ports))}, запрос шаблонов Strix...")

            session_id = None
            alive_found = []
            probe_data = {}

            try:
                probe_resp = await client.get(f"{STRIX_API_URL}/api/probe", params={"ip": ip}, timeout=8.0)
                probe_data = probe_resp.json() if probe_resp.status_code == 200 else {}
                probes = probe_data.get("probes") or {}

                stream_params = {"ids": ids or "p:top-150", "ip": ip}
                if user:
                    stream_params["user"] = user
                if password:
                    stream_params["pass"] = password
                if channel:
                    stream_params["channel"] = channel
                if ports:
                    stream_params["ports"] = ports
                elif open_ports:
                    stream_params["ports"] = ",".join(str(p) for p in open_ports)
                else:
                    ports_obj = probes.get("ports") if isinstance(probes, dict) else None
                    if isinstance(ports_obj, dict) and ports_obj.get("open"):
                        stream_params["ports"] = ",".join(str(p) for p in ports_obj["open"])

                streams_resp = await client.get(f"{STRIX_API_URL}/api/streams", params=stream_params, timeout=8.0)
                streams = streams_resp.json().get("streams", []) if streams_resp.status_code == 200 else []

                if not streams:
                    async with lock:
                        job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Нет сгенерированных путей потока")
                    return

                try:
                    test_resp = await client.post(
                        f"{STRIX_API_URL}/api/test",
                        json={"sources": {"streams": streams}},
                        timeout=8.0,
                    )
                    if test_resp.status_code != 200:
                        async with lock:
                            job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Ошибка создания сессии ({test_resp.status_code})")
                        return

                    session_id = test_resp.json().get("session_id")
                    start_poll = asyncio.get_event_loop().time()
                    while (asyncio.get_event_loop().time() - start_poll) < 45.0:
                        if is_cancelled():
                            return
                        await asyncio.sleep(1.0)
                        poll_resp = await client.get(f"{STRIX_API_URL}/api/test", params={"id": session_id}, timeout=6.0)
                        if poll_resp.status_code != 200:
                            break

                        pdata = poll_resp.json()
                        results = pdata.get("results") or []
                        for r in results:
                            if r not in alive_found:
                                alive_found.append(r)

                        if pdata.get("status") == "done":
                            break

                    if alive_found:
                        # 1. Filter out phantom paths and fake HTML screenshots (e.g. TP-Link routers returning 401 HTML)
                        verified = []
                        for idx_r, r in enumerate(alive_found):
                            codecs = [str(c).upper() for c in (r.get("codecs") or [])]
                            has_video_codec = any(c in ("H264", "H265", "HEVC", "MPEG4", "MJPEG") for c in codecs)
                            has_dimensions = bool(r.get("width") and r.get("height"))
                            sc_path = str(r.get("screenshot") or "").strip()

                            if has_video_codec or has_dimensions:
                                verified.append(r)
                            elif sc_path and session_id:
                                sc_bytes = await _download_strix_screenshot(client, session_id, idx_r, sc_path)
                                if sc_bytes and _is_valid_image_bytes(sc_bytes):
                                    r["_valid_screenshot_bytes"] = sc_bytes
                                    verified.append(r)

                        if strict_video_only and verified:
                            alive_found = verified
                        elif strict_video_only and not verified:
                            # Quick fallback verification for candidate paths with ffmpeg (max 3)
                            tested_alive = []
                            for cand in alive_found[:3]:
                                cand_url = str(cand.get("source") or "").strip()
                                if not cand_url:
                                    continue
                                cand_hash = hashlib.md5(cand_url.encode("utf-8")).hexdigest()
                                cand_file = STRIX_CAPTURE_DIR / f"{cand_hash}.jpg"
                                ok = await extract_stream_frame(cand_url, cand_file)
                                if ok:
                                    cand["screenshot"] = f"preview?url={cand_url}"
                                    tested_alive.append(cand)
                            alive_found = tested_alive

                        if alive_found:
                            # Prioritize verified streams with codecs, resolution or screenshot first
                            alive_found = sorted(alive_found, key=lambda s: (
                                0 if (s.get("screenshot") and s.get("codecs")) else
                                1 if (s.get("codecs") or (s.get("width") and s.get("height"))) else
                                2 if s.get("screenshot") else
                                3
                            ))
                            ip_item = {
                                "ip": ip,
                                "probe": probe_data,
                                "session_id": session_id,
                                "streams": alive_found,
                                "timestamp": datetime.now().isoformat(),
                            }
                            async with lock:
                                job["results"].append(ip_item)
                                results_cache.insert(0, ip_item)
                                try:
                                    storage.save_strix_result(ip, session_id, probe_data, alive_found, overwrite=strict_video_only)
                                except Exception as err:
                                    logger.error("Failed to save strix result to SQLite: %s", err)
                                job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Подтверждено {len(alive_found)} живых видеопотоков!")

                            safe_session = re.sub(r'[^a-zA-Z0-9_-]', '_', session_id) if session_id else ""
                            for stream_idx, st_info in enumerate(alive_found):
                                src_url = str(st_info.get("source") or "").strip()
                                url_hash = hashlib.md5(src_url.encode("utf-8")).hexdigest() if src_url else ""
                                try:
                                    c_file = STRIX_CAPTURE_DIR / f"{safe_session}_{stream_idx}.jpg" if safe_session else None
                                    h_file = STRIX_CAPTURE_DIR / f"{url_hash}.jpg" if url_hash else None
                                    sc_content = st_info.get("_valid_screenshot_bytes")
                                    if not sc_content:
                                        sc_path = str(st_info.get("screenshot") or "").strip()
                                        sc_content = await _download_strix_screenshot(client, session_id, stream_idx, sc_path)

                                    if sc_content and _is_valid_image_bytes(sc_content):
                                        if c_file:
                                            c_file.write_bytes(sc_content)
                                        if h_file:
                                            h_file.write_bytes(sc_content)
                                except Exception:
                                    pass
                        else:
                            try:
                                storage.set_strix_garbage_status(ip, True)
                            except Exception:
                                pass
                            async with lock:
                                job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Фантомные RTSP-пути отсеяны (нет активного видео)")
                    else:
                        async with lock:
                            job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Активных потоков не найдено")

                finally:
                    if session_id:
                        for _ in range(2):
                            try:
                                del_resp = await client.delete(f"{STRIX_API_URL}/api/test", params={"id": session_id}, timeout=3.0)
                                if del_resp.status_code == 200:
                                    break
                            except Exception:
                                await asyncio.sleep(0.3)

            except Exception as exc:
                async with lock:
                    job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {ip}: Ошибка ({exc})")
            finally:
                async with lock:
                    stage2_completed += 1
                    pct = 40 + round((stage2_completed / max(1, total_stage2)) * 60)
                    job["progress_pct"] = min(99, pct)
                    now_t = asyncio.get_event_loop().time()
                    elapsed2 = max(0.1, now_t - stage2_start_t)
                    speed2 = (stage2_completed / elapsed2) * 60
                    eta2_sec = (total_stage2 - stage2_completed) / max(0.0001, (stage2_completed / elapsed2))
                    eta2_str = _format_eta(eta2_sec)
                    job["stage"] = f"Этап 2/2: Анализ Strix [{stage2_completed}/{total_stage2}] {ip} (найдено камер: {len(job['results'])}, {speed2:.1f} хост/мин, ост. {eta2_str})"
                    if len(job["logs"]) > 120:
                        job["logs"] = job["logs"][-120:]

                    if now_t - last_update_t > 2.0:
                        last_update_t = now_t
                        try:
                            storage.update_strix_job_progress(
                                job_id,
                                stage2_completed,
                                ip,
                                job["progress_pct"],
                                job["stage"],
                                status="running",
                                logs=job["logs"],
                            )
                        except Exception:
                            pass

    async with httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)) as client:
        tasks = [probe_strix_host(client, ip, open_ports, idx) for idx, (ip, open_ports) in enumerate(responsive_hosts)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Periodic cleanup of orphaned sessions
        try:
            s_list_resp = await client.get(f"{STRIX_API_URL}/api/test", timeout=3.0)
            if s_list_resp.status_code == 200:
                for s in s_list_resp.json().get("sessions", []):
                    sid = s.get("session_id")
                    if sid:
                        await client.delete(f"{STRIX_API_URL}/api/test", params={"id": sid}, timeout=2.0)
        except Exception:
            pass

    final_status = "cancelled" if is_cancelled() else "completed"
    job["status"] = final_status
    if final_status == "completed":
        job["progress_pct"] = 100
        job["stage"] = f"Сканирование завершено: проверено {len(targets)} IP ({len(responsive_hosts)} с портами), найдено {len(job['results'])} камер"
        _save_completed_cidrs(storage, job_id, len(targets), len(job["results"]))
    else:
        job["stage"] = "Сканирование прервано пользователем"

    try:
        storage.update_strix_job_progress(
            job_id,
            len(targets),
            job.get("current_ip", ""),
            job["progress_pct"],
            job["stage"],
            status=final_status,
            logs=job["logs"],
        )
    except Exception:
        pass


def _save_completed_cidrs(storage: StorageManager, job_id: str, total_ips: int, cameras_found: int):
    """Save all completed CIDRs from job input parameters into SQLite."""
    try:
        db_job = storage.get_strix_job(job_id)
        params = db_job.get("params", {}) if db_job else {}
        input_cidrs = params.get("input_cidrs", [])
        for cidr in input_cidrs:
            storage.save_strix_scanned_cidr(
                cidr=cidr,
                total_ips=total_ips,
                cameras_found=cameras_found,
            )
    except Exception as exc:
        logger.error("Failed to record scanned CIDRs in SQLite: %s", exc)
