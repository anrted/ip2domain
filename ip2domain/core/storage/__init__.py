"""Modular StorageManager package for SQLite persistence."""
from ip2domain.core.storage.base import BaseStorage, DB_PATH
from ip2domain.core.storage.recon import ReconStorageMixin
from ip2domain.core.storage.jobs import JobsStorageMixin
from ip2domain.core.storage.analysis import AnalysisStorageMixin
from ip2domain.core.storage.cameras import CamerasStorageMixin
from ip2domain.core.storage.centra import CentraStorageMixin
from ip2domain.core.storage.strix import StrixStorageMixin
from ip2domain.core.storage.remote_desktop import RemoteDesktopStorageMixin
from ip2domain.core.storage.go2rtc import Go2rtcStorageMixin
from ip2domain.core.storage.scanner_v2 import ScannerV2StorageMixin

class StorageManager(
    BaseStorage,
    ReconStorageMixin,
    JobsStorageMixin,
    AnalysisStorageMixin,
    CamerasStorageMixin,
    CentraStorageMixin,
    StrixStorageMixin,
    RemoteDesktopStorageMixin,
    Go2rtcStorageMixin,
    ScannerV2StorageMixin,
):
    """
    Unified SQLite persistence manager assembling all domain-specific mixins.
    Fully backwards-compatible with legacy StorageManager.
    """
    pass

__all__ = ["StorageManager", "DB_PATH"]
