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
from .stage3_stream import _valid_frame, verify_camera_streams
from .models import CameraResult
from ip2domain.scanning.runner import run_bounded

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
        max_streams_per_cam: int = 0,
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

                if only_unverified and all(
                    s.get("verified") and s.get("screenshot") and _valid_frame(Path(s["screenshot"]))
                    for s in streams
                ):
                    continue

                cameras_to_process.append(cam)

            # Prioritize cameras with RTSP / Snapshot streams
            self._progress.total_cameras = len(cameras_to_process)
            self._progress.total_streams = sum(
                sum(not (only_unverified and s.get("verified") and s.get("screenshot") and _valid_frame(Path(s["screenshot"])))
                    for s in (c.get("streams", [])[:max_streams_per_cam] if max_streams_per_cam > 0 else c.get("streams", [])))
                for c in cameras_to_process
            )

            if not cameras_to_process:
                self._progress.is_running = False
                return

            async def process_camera(cam: dict):
                if self._progress.stop_requested:
                    return

                ip = str(cam.get("ip", "")).strip()
                self._progress.current_ip = ip
                camera = CameraResult.from_dict(cam)
                selected = camera.streams[:max_streams_per_cam] if max_streams_per_cam > 0 else camera.streams
                for stream in selected:
                    if self._progress.stop_requested:
                        break
                    if only_unverified and stream.verified and stream.screenshot_path and _valid_frame(Path(stream.screenshot_path)):
                        continue
                    # A single-stream view keeps per-stream progress/save and all
                    # other endpoint metadata intact in the parent result.
                    single = CameraResult(ip=ip, streams=[stream], credentials=camera.credentials)
                    await verify_camera_streams(single, _V2_CAPTURE_DIR,
                                                is_cancelled=lambda: self._progress.stop_requested)
                    self._progress.processed_streams += 1
                    if stream.verified:
                        self._progress.verified_streams += 1
                    else:
                        self._progress.failed_streams += 1
                    updated = dict(cam, **camera.to_dict())
                    storage.save_v2_result(updated)

                self._progress.processed_cameras += 1

            await run_bounded(cameras_to_process, process_camera, concurrency,
                              lambda: self._progress.stop_requested)

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
