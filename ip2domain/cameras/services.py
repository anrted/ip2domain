import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable

from ip2domain.core.storage import StorageManager

from .models import Camera
from .providers import ProviderRegistry


class CameraCatalogService:
    def __init__(self, storage: StorageManager, providers: ProviderRegistry):
        self.storage = storage
        self.providers = providers

    def upsert(self, provider_id: str, raw_cameras: Iterable[Dict[str, Any]]) -> list:
        provider = self.providers.require(provider_id)
        cameras = [provider.normalize(raw) for raw in raw_cameras]
        payloads = [camera.to_dict() for camera in cameras]
        self.storage.save_cameras(provider.provider_id, payloads)
        return [self.storage.get_camera(provider.provider_id, camera.external_id) for camera in cameras]

    def get(self, provider_id: str, external_id: str) -> Dict[str, Any] | None:
        return self.storage.get_camera(provider_id, external_id)


class SnapshotCache:
    """Provider-safe disk keys; storage backend can later be replaced by S3."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, provider_id: str, external_id: str) -> Path:
        provider = provider_id.strip().lower()
        digest = hashlib.sha256(external_id.encode("utf-8")).hexdigest()
        directory = self.root / provider / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{digest}.jpg"

    def candidates(self, registry: ProviderRegistry, camera_data: Dict[str, Any]):
        provider = registry.require(str(camera_data["provider_id"]))
        camera = provider.normalize(camera_data)
        return [url for url in provider.snapshot_candidates(camera) if provider.validate_url(url)]
