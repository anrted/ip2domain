import re
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

from .models import Camera, CameraEndpoint, ProviderCapabilities
from .providers import CameraProvider


class CentraProvider(CameraProvider):
    provider_id = "centra"
    display_name = "Centra"
    capabilities = {ProviderCapabilities.DISCOVERY, ProviderCapabilities.SNAPSHOT,
                    ProviderCapabilities.STREAM, ProviderCapabilities.EMBED,
                    ProviderCapabilities.GEOCODING}
    CAMERA_ID = re.compile(r"[A-Z]-\d+-\d+", re.IGNORECASE)
    HOST = re.compile(r"(?:flus\d*|[a-z0-9-]+)\.mycentra\.ru", re.IGNORECASE)

    def normalize(self, raw: Dict[str, Any]) -> Camera:
        external_id = str(raw.get("external_id") or raw.get("id") or "").upper()
        if not self.CAMERA_ID.fullmatch(external_id):
            raise ValueError("Invalid Centra camera id")
        host = str(raw.get("stream_host") or urlparse(str(raw.get("embed_url") or "")).hostname or "")
        endpoints = [CameraEndpoint(str(item.get("kind") or ""), str(item.get("url") or ""),
                                    int(item.get("priority") or 0), dict(item.get("metadata") or {}))
                     for item in (raw.get("endpoints") or [])]
        if host and self.HOST.fullmatch(host):
            endpoints.extend([
                CameraEndpoint("snapshot", f"https://{host}/{external_id}/preview.jpg", 100),
                CameraEndpoint("hls", f"https://{host}/{external_id}/tracks-v1/index.m3u8", 50),
                CameraEndpoint("hls", f"https://{host}/{external_id}/index.m3u8", 40),
                CameraEndpoint("embed", f"https://{host}/{external_id}/embed.html", 100),
            ])
        reserved = {"id", "external_id", "title", "address", "camera_type", "available",
                    "coordinates", "latitude", "longitude", "endpoints"}
        coordinates = raw.get("coordinates") or [None, None]
        return Camera(provider_id=self.provider_id, external_id=external_id,
                      title=str(raw.get("title") or external_id), address=str(raw.get("address") or ""),
                      camera_type=str(raw.get("camera_type") or external_id.split("-", 1)[0]).upper(),
                      available=bool(raw.get("available", True)), latitude=raw.get("latitude", coordinates[0]),
                      longitude=raw.get("longitude", coordinates[1]), endpoints=endpoints,
                      metadata={key: value for key, value in raw.items() if key not in reserved})

    def validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme == "https" and parsed.port is None and bool(self.HOST.fullmatch(parsed.hostname or ""))

    def snapshot_candidates(self, camera: Camera) -> Iterable[str]:
        return super().snapshot_candidates(camera)
