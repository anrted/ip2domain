from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, Iterable, Optional, Set

from .models import Camera, ProviderCapabilities


class CameraProvider(ABC):
    """Boundary between provider-specific protocols and the camera domain."""

    provider_id: str
    display_name: str
    capabilities: Set[ProviderCapabilities] = set()

    def describe(self) -> Dict[str, Any]:
        return {"id": self.provider_id, "name": self.display_name,
                "capabilities": sorted(item.value for item in self.capabilities)}

    @abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> Camera:
        raise NotImplementedError

    async def discover(self, request: Dict[str, Any]) -> AsyncIterator[Camera]:
        if False:
            yield self.normalize(request)
        raise NotImplementedError(f"{self.provider_id} does not support discovery")

    def snapshot_candidates(self, camera: Camera) -> Iterable[str]:
        return (endpoint.url for endpoint in camera.endpoints if endpoint.kind == "snapshot")

    def stream_candidates(self, camera: Camera) -> Iterable[str]:
        return (endpoint.url for endpoint in camera.endpoints if endpoint.kind in {"hls", "rtsp"})

    def validate_url(self, url: str) -> bool:
        """Providers must explicitly allow every URL fetched by backend services."""
        return False


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: Dict[str, CameraProvider] = {}

    def register(self, provider: CameraProvider) -> CameraProvider:
        key = provider.provider_id.strip().lower()
        if not key or key in self._providers:
            raise ValueError(f"Duplicate or empty camera provider: {key}")
        self._providers[key] = provider
        return provider

    def get(self, provider_id: str) -> Optional[CameraProvider]:
        return self._providers.get(provider_id.strip().lower())

    def require(self, provider_id: str) -> CameraProvider:
        provider = self.get(provider_id)
        if not provider:
            raise KeyError(provider_id)
        return provider

    def describe(self):
        return [provider.describe() for provider in self._providers.values()]
