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
    status: str = "idle"
    is_running: bool = False
    total_cameras: int = 0
    processed_cameras: int = 0
    total_streams: int = 0
    processed_streams: int = 0
    verified_streams: int = 0
    failed_streams: int = 0
    unsupported_streams: int = 0
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
        if max_streams_per_cam < 0:
            raise ValueError("max_streams_per_cam must be non-negative")
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
                status="running", is_running=True,
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
            self._progress.status = "stopping"
            return {"success": True, "message": "Остановка запрошена"}

    @staticmethod
    def _prepare_cameras(raw_cams, only_unverified, max_streams_per_cam):
        prepared = []
        for cam in raw_cams:
            selected = []
            seen = set()
            for stream in cam.get("streams", []):
                url = stream.get("url")
                if not url or url in seen:
                    continue
                seen.add(url)
                if only_unverified and stream.get("verified") and stream.get("screenshot") and _valid_frame(Path(stream["screenshot"])):
                    continue
                selected.append(stream)
            if max_streams_per_cam > 0:
                selected = selected[:max_streams_per_cam]
            if selected:
                prepared.append(dict(cam, streams=selected))
        return prepared

    async def _run(
        self,
        concurrency: int,
        only_unverified: bool,
        max_streams_per_cam: int,
        target_ips: Optional[List[str]],
    ):
        try:
            # 1. Fetch cameras from database
            raw_cams = await asyncio.to_thread(storage.get_v2_results, limit=0)
            if target_ips is not None:
                target_set = {str(ip).strip() for ip in target_ips}
                raw_cams = [c for c in raw_cams if str(c.get("ip", "")).strip() in target_set]

            cameras_to_process = await asyncio.to_thread(
                self._prepare_cameras, raw_cams, only_unverified, max_streams_per_cam)
            self._progress.total_cameras = len(cameras_to_process)
            self._progress.total_streams = sum(len(c["streams"]) for c in cameras_to_process)

            if not cameras_to_process:
                self._progress.status = "completed"
                return

            async def process_camera(cam: dict):
                if self._progress.stop_requested:
                    return

                ip = str(cam.get("ip", "")).strip()
                self._progress.current_ip = ip
                camera = CameraResult.from_dict(cam)
                for stream in camera.streams:
                    if self._progress.stop_requested:
                        break
                    # A single-stream view keeps per-stream progress/save and all
                    # other endpoint metadata intact in the parent result.
                    single = CameraResult(ip=ip, streams=[stream], credentials=camera.credentials)
                    await verify_camera_streams(single, _V2_CAPTURE_DIR,
                                                is_cancelled=lambda: self._progress.stop_requested)
                    self._progress.processed_streams += 1
                    if stream.verified:
                        self._progress.verified_streams += 1
                    elif stream.verification_status == "unsupported":
                        self._progress.unsupported_streams += 1
                    else:
                        self._progress.failed_streams += 1
                    # Save just the changed stream; another request may have
                    # refreshed metadata/other streams while this one was captured.
                    await asyncio.to_thread(storage.update_v2_stream, ip, stream.to_dict())

                self._progress.processed_cameras += 1

            await run_bounded(cameras_to_process, process_camera, concurrency,
                              lambda: self._progress.stop_requested)

            self._progress.status = "cancelled" if self._progress.stop_requested else "completed"
        except asyncio.CancelledError:
            self._progress.status = "cancelled"
            self._progress.stop_requested = True
            logger.info("[BulkCapture] Task cancelled")
        except Exception as exc:
            logger.exception("[BulkCapture] Fatal error during bulk capture: %s", exc)
            self._progress.error = str(exc)
            self._progress.status = "error"
        finally:
            self._progress.is_running = False
            self._progress.current_ip = ""
            if self._progress.started_at > 0:
                self._progress.elapsed_seconds = int(time.time() - self._progress.started_at)
            gc.collect()


# Global singleton manager
bulk_capture_mgr = BulkCaptureManager()
