import ipaddress
from typing import Any, Dict
from urllib.parse import urlparse

from .models import Camera, CameraEndpoint, ProviderCapabilities
from .providers import CameraProvider


class GenericIPCameraProvider(CameraProvider):
    """Explicitly configured IP/HTTP/HLS/RTSP cameras; no unsafe network scanning."""

    provider_id = "generic-ip"
    display_name = "Generic IP camera"
    capabilities = {ProviderCapabilities.SNAPSHOT, ProviderCapabilities.STREAM}

    def normalize(self, raw: Dict[str, Any]) -> Camera:
        external_id = str(raw.get("external_id") or raw.get("id") or "").strip()
        if not external_id:
            raise ValueError("external_id is required")
        endpoints = []
        for item in raw.get("endpoints") or []:
            endpoint = CameraEndpoint(str(item.get("kind") or ""), str(item.get("url") or ""),
                                      int(item.get("priority") or 0), dict(item.get("metadata") or {}))
            if endpoint.kind not in {"snapshot", "hls", "rtsp"} or not self.validate_url(endpoint.url):
                raise ValueError("Invalid or unsupported camera endpoint")
            endpoints.append(endpoint)
        return Camera(provider_id=self.provider_id, external_id=external_id,
                      title=str(raw.get("title") or external_id), address=str(raw.get("address") or ""),
                      camera_type=str(raw.get("camera_type") or "ip"), available=bool(raw.get("available", True)),
                      latitude=raw.get("latitude"), longitude=raw.get("longitude"), endpoints=endpoints,
                      metadata=dict(raw.get("metadata") or {}))

    def validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "rtsp"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            return False
        return True
