"""Camera Scanner v2 — Safe Background Bulk Preview and Stream Verification.

Verifies streams and fetches preview snapshots for cameras in the database.
Designed with strict concurrency and resource limits for low-spec servers (1 vCPU / 2GB RAM):
- Fixed low concurrency (default 2 workers, max 3)
- Single-threaded ffmpeg subprocesses with strict timeouts
- HTTP snapshot prioritization before ffmpeg
- Fast skip for already verified streams/files
- Real-time status reporting and graceful stop capability
"""
from __future__ import annotations

import asyncio
import gc
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ip2domain.core.storage import StorageManager
from .stage3_stream import _capture_path, _download_http_snapshot, capture_stream_frame

logger = logging.getLogger(__name__)

storage = StorageManager()

_V2_CAPTURE_DIR = Path(__file__).resolve().parent.parent.parent / "web" / "v2_captures"
_V2_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class BulkCaptureProgress:
    is_running: bool = False
    total_cameras: int = 0
    processed_cameras: int = 0
    total_streams: int = 0
    processed_streams: int = 0
    verified_streams: int = 0
    failed_streams: int = 0
    current_ip: str = ""
    started_at: float = 0.0
    elapsed_seconds: int = 0
    stop_requested: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.is_running and self.started_at > 0:
            d["elapsed_seconds"] = int(time.time() - self.started_at)
        return d


class BulkCaptureManager:
    """Manages background batch verification of camera streams."""

    def __init__(self):
        self._progress = BulkCaptureProgress()
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    def get_status(self) -> dict:
        return self._progress.to_dict()

    async def start(
        self,
        concurrency: int = 2,
        only_unverified: bool = True,
        max_streams_per_cam: int = 4,
        target_ips: Optional[List[str]] = None,
    ) -> dict:
        async with self._lock:
            if self._progress.is_running:
                return {
                    "success": False,
                    "message": "Процесс массового получения превью уже запущен",
                    "status": self.get_status(),
                }

            # Clamp concurrency to protect low-resource servers
            safe_concurrency = max(1, min(concurrency, 3))

            self._progress = BulkCaptureProgress(
                is_running=True,
                started_at=time.time(),
                stop_requested=False,
            )

            self._task = asyncio.create_task(
                self._run(
                    concurrency=safe_concurrency,
                    only_unverified=only_unverified,
                    max_streams_per_cam=max_streams_per_cam,
                    target_ips=target_ips,
                )
            )

            return {
                "success": True,
                "message": "Массовое получение превью запущено",
                "status": self.get_status(),
            }

    async def stop(self) -> dict:
        async with self._lock:
            if not self._progress.is_running:
                return {"success": True, "message": "Процесс не запущен"}
            self._progress.stop_requested = True
            return {"success": True, "message": "Остановка запрошена"}

    async def _run(
        self,
        concurrency: int,
        only_unverified: bool,
        max_streams_per_cam: int,
        target_ips: Optional[List[str]],
    ):
        try:
            # 1. Fetch cameras from database
            raw_cams = storage.get_v2_results(limit=100000)
            if target_ips:
                target_set = {str(ip).strip() for ip in target_ips}
                raw_cams = [c for c in raw_cams if str(c.get("ip", "")).strip() in target_set]

            cameras_to_process = []
            for cam in raw_cams:
                streams = cam.get("streams", [])
                if not streams:
                    continue

                if only_unverified:
                    # Check if camera already has at least one verified stream with existing file
                    has_verified_screenshot = False
                    for s in streams:
                        sc = s.get("screenshot", "")
                        if sc and Path(sc).exists() and Path(sc).stat().st_size >= 2048:
                            has_verified_screenshot = True
                            break
                    if has_verified_screenshot:
                        # Skip cameras that already have valid preview
                        continue

                cameras_to_process.append(cam)

            # Prioritize cameras with RTSP / Snapshot streams
            self._progress.total_cameras = len(cameras_to_process)
            self._progress.total_streams = sum(
                min(len(c.get("streams", [])), max_streams_per_cam) for c in cameras_to_process
            )

            if not cameras_to_process:
                self._progress.is_running = False
                return

            semaphore = asyncio.Semaphore(concurrency)

            async def process_camera(cam: dict):
                if self._progress.stop_requested:
                    return

                ip = str(cam.get("ip", "")).strip()
                self._progress.current_ip = ip
                credentials = cam.get("credentials") or {}
                streams = cam.get("streams", [])
                changed = False

                tested_count = 0
                for s in streams:
                    if self._progress.stop_requested:
                        break
                    if tested_count >= max_streams_per_cam:
                        break

                    url = s.get("url", "")
                    if not url:
                        continue

                    # If already verified and file exists, count as verified
                    existing_path = s.get("screenshot", "")
                    if existing_path and Path(existing_path).exists() and Path(existing_path).stat().st_size >= 2048:
                        s["verified"] = True
                        self._progress.verified_streams += 1
                        self._progress.processed_streams += 1
                        continue

                    stype = s.get("type", "rtsp")
                    ok = False
                    path = ""
                    codec, w, h = "", 0, 0

                    tested_count += 1

                    # 1. Try HTTP snapshot download first if applicable (fast, low CPU)
                    is_http_snap = (
                        stype == "http_snapshot"
                        or (
                            url.startswith(("http://", "https://"))
                            and ".m3u8" not in url
                            and "mjpg" not in url.lower()
                            and "video.cgi" not in url.lower()
                        )
                    )
                    if is_http_snap:
                        snap_path = await _download_http_snapshot(url, _V2_CAPTURE_DIR, credentials=credentials)
                        if snap_path and Path(snap_path).exists() and Path(snap_path).stat().st_size >= 2048:
                            ok = True
                            path = snap_path
                            codec = "JPEG"

                    # 2. Try ffmpeg capture for RTSP / RTMP / HLS / MJPEG
                    if not ok:
                        stream_type = (
                            "rtmp" if url.startswith("rtmp://")
                            else ("hls" if ".m3u8" in url
                            else ("mjpeg" if ("mjpg" in url.lower() or "video.cgi" in url.lower())
                            else "rtsp"))
                        )
                        ok, path, codec, w, h = await capture_stream_frame(
                            stream_url=url,
                            stream_type=stream_type,
                            capture_dir=_V2_CAPTURE_DIR,
                            credentials=credentials,
                        )

                    self._progress.processed_streams += 1

                    if ok and path and Path(path).exists() and Path(path).stat().st_size > 500:
                        s["verified"] = True
                        s["screenshot"] = path
                        s["codec"] = codec
                        s["resolution"] = f"{w}x{h}" if w and h else ""
                        s["width"] = w
                        s["height"] = h
                        self._progress.verified_streams += 1
                        changed = True
                        # If we confirmed one stream on this camera, we can continue to others or prioritize
                    else:
                        self._progress.failed_streams += 1

                    # Short yield to prevent CPU starvation
                    await asyncio.sleep(0.05)

                if changed:
                    # Save updated camera result
                    try:
                        storage.save_v2_result(cam)
                    except Exception as e:
                        logger.warning("[BulkCapture] Failed to save camera %s: %s", ip, e)

                self._progress.processed_cameras += 1

            # Process in controlled chunks
            chunk_size = 20
            for i in range(0, len(cameras_to_process), chunk_size):
                if self._progress.stop_requested:
                    break
                chunk = cameras_to_process[i : i + chunk_size]

                async def sem_task(c):
                    async with semaphore:
                        await process_camera(c)

                await asyncio.gather(*(sem_task(c) for c in chunk), return_exceptions=True)

                # Periodic garbage collection for low RAM environment
                if i % 100 == 0:
                    gc.collect()

                await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info("[BulkCapture] Task cancelled")
        except Exception as exc:
            logger.exception("[BulkCapture] Fatal error during bulk capture: %s", exc)
            self._progress.error = str(exc)
        finally:
            self._progress.is_running = False
            self._progress.current_ip = ""
            if self._progress.started_at > 0:
                self._progress.elapsed_seconds = int(time.time() - self._progress.started_at)
            gc.collect()


# Global singleton manager
bulk_capture_mgr = BulkCaptureManager()
