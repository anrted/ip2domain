"""Shared dependencies and state singletons for web routers."""
import os
import time
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

def _centra_capture_is_stale(path: Path, ttl: int) -> bool:
    try:
        return not path.is_file() or time.time() - path.stat().st_mtime >= ttl
    except OSError:
        return True

from ip2domain.core.storage import StorageManager
from ip2domain.web.auth import AuthManager
from ip2domain.cameras.centra import CentraProvider
from ip2domain.cameras.generic_ip import GenericIPCameraProvider
from ip2domain.cameras.providers import ProviderRegistry
from ip2domain.cameras.services import CameraCatalogService, SnapshotCache

_WEB_DIR = Path(__file__).resolve().parent.parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"

storage = StorageManager()
auth_manager = AuthManager(storage.db_path)

camera_providers = ProviderRegistry()
camera_providers.register(CentraProvider())
camera_providers.register(GenericIPCameraProvider())
camera_catalog = CameraCatalogService(storage, camera_providers)

class JobStore:
    """Hybrid job state manager with SQLite persistence."""
    def __init__(self, storage_manager: StorageManager, job_type: str):
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._storage = storage_manager
        self._job_type = job_type

    def _persist(self, job_id: str, state: dict) -> None:
        try:
            target = str(state.get("target") or "")
            status = str(state.get("status") or "queued")
            progress_pct = int(state.get("progress_pct") or 0)
            stage = str(state.get("stage") or "")
            error = state.get("error")
            meta = {k: v for k, v in state.items() if k not in ("job_id", "job_type", "target", "status", "progress_pct", "stage", "error")}
            self._storage.upsert_job(
                job_id=job_id,
                job_type=self._job_type,
                target=target,
                status=status,
                progress_pct=progress_pct,
                stage=stage,
                error=str(error) if error else None,
                meta=meta,
            )
        except Exception as e:
            logger.error(f"Failed to persist job {job_id}: {e}")

    def create(self, job_id: str, initial_state: dict) -> dict:
        self._mem[job_id] = initial_state.copy()
        self._persist(job_id, self._mem[job_id])
        return self._mem[job_id]

    def update(self, job_id: str, **kwargs) -> None:
        if job_id in self._mem:
            self._mem[job_id].update(kwargs)
            self._persist(job_id, self._mem[job_id])

    def get(self, job_id: str) -> Any:
        if job_id in self._mem:
            return self._mem[job_id]
        return self._storage.get_job(job_id)

    def __contains__(self, job_id: str) -> bool:
        return job_id in self._mem

    def __getitem__(self, job_id: str) -> Dict[str, Any]:
        return self._mem[job_id]

    def __setitem__(self, job_id: str, value: dict) -> None:
        self._mem[job_id] = value
        self._persist(job_id, value)

    def __delitem__(self, job_id: str) -> None:
        self._mem.pop(job_id, None)

    def items(self):
        return self._mem.items()

JOBS = JobStore(storage, job_type='scan')
VULN_JOBS = JobStore(storage, job_type='vuln')
REMOTE_DESKTOP_JOBS = JobStore(storage, job_type='remote_desktop')
CAMERA_JOBS = JobStore(storage, job_type='camera')
CAMERA_CANCEL_EVENTS: Dict[str, asyncio.Event] = {}
CENTRA_JOBS = JobStore(storage, job_type='centra_discovery')
HTTP_CACHE: Dict[str, Dict[str, Any]] = {}

REMOTE_CAPTURE_DIR = _WEB_DIR / "captures"
REMOTE_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

CENTRA_CAPTURE_DIR = _WEB_DIR / "centra_captures"
CENTRA_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

CAMERA_CAPTURE_DIR = _WEB_DIR / "camera_captures"
CAMERA_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
CAMERA_SNAPSHOT_CACHE = SnapshotCache(CAMERA_CAPTURE_DIR)

STRIX_CAPTURE_DIR = _WEB_DIR / "strix_captures"
STRIX_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

CAMERA_CAPTURE_LOCKS: Dict[str, asyncio.Lock] = {}
CAMERA_PREVIEW_SEMAPHORE = asyncio.Semaphore(max(
    1, min(50, int(os.environ.get("IP2DOMAIN_CAMERA_PREVIEW_CONCURRENCY", "12")))))

IP_CAMERA_PREVIEW_SEMAPHORE = asyncio.Semaphore(max(
    1, min(4, int(os.environ.get("IP2DOMAIN_IP_CAMERA_PREVIEW_CONCURRENCY", "2")))))
IP_CAMERA_STREAM_SEMAPHORE = asyncio.Semaphore(max(
    1, min(4, int(os.environ.get("IP2DOMAIN_IP_CAMERA_STREAM_CONCURRENCY", "1")))))
IP_CAMERA_PREVIEW_LOCKS: Dict[str, asyncio.Lock] = {}
IP_CAMERA_CONNECTIONS: Dict[str, dict] = {}

COMMON_RTSP_PATHS = (
    "/", "/11", "/12", "/1/h264major", "/1/h264minor",
    "/live.sdp", "/h264.sdp", "/stream1", "/live/ch0",
    "/Streaming/Channels/1", "/Streaming/Channels/101",
    "/cam/realmonitor?channel=1&subtype=0",
    "/CAM_ID.password.mp2"
)

CENTRA_PREVIEW_CONCURRENCY = max(1, min(50, int(os.environ.get("IP2DOMAIN_CENTRA_PREVIEW_CONCURRENCY", "12"))))
CENTRA_FFMPEG_CONCURRENCY = max(1, min(8, int(os.environ.get("IP2DOMAIN_CENTRA_FFMPEG_CONCURRENCY", "4"))))
CENTRA_PREVIEW_SEMAPHORE = asyncio.Semaphore(CENTRA_PREVIEW_CONCURRENCY)
CENTRA_FFMPEG_SEMAPHORE = asyncio.Semaphore(CENTRA_FFMPEG_CONCURRENCY)
CENTRA_PERSON_FFMPEG_SEMAPHORE = asyncio.Semaphore(1)
CENTRA_CAPTURE_LOCKS: Dict[str, asyncio.Lock] = {}
CENTRA_CAPTURE_REFRESH_TASKS: Dict[str, asyncio.Task] = {}
CENTRA_CAPTURE_LAST_CLEANUP = 0.0
CENTRA_PERSON_MODEL = _WEB_DIR.parent / "models" / "yolo11n.onnx"
CENTRA_PERSON_JOBS: Dict[str, dict] = {}

GO2RTC_API_URL = os.environ.get("GO2RTC_API_URL", "http://127.0.0.1:1984")
GO2RTC_WS_URL = os.environ.get("GO2RTC_WS_URL", "ws://127.0.0.1:1984")

STRIX_API_URL = os.environ.get("STRIX_API_URL", "http://127.0.0.1:4567")
STRIX_FFMPEG_SEMAPHORE = asyncio.Semaphore(max(1, min(6, int(os.environ.get("IP2DOMAIN_STRIX_FFMPEG_CONCURRENCY", "3")))))
STRIX_CAPTURE_LOCKS: Dict[str, asyncio.Lock] = {}
strix_jobs: Dict[str, Dict[str, Any]] = {}
strix_results_cache: list = []
