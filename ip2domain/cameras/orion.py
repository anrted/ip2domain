"""Orion Telecom (cam.krk.ru) camera provider.

Extracts tokenless open public cameras from Orion Telecom Flussonic network.
"""
import json
import logging
import re
import urllib.request
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .models import Camera, CameraEndpoint, ProviderCapabilities
from .providers import CameraProvider

logger = logging.getLogger(__name__)


class OrionProvider(CameraProvider):
    provider_id = "orion"
    display_name = "Орион Телеком (cam.krk.ru)"
    capabilities = {
        ProviderCapabilities.DISCOVERY,
        ProviderCapabilities.SNAPSHOT,
        ProviderCapabilities.STREAM,
        ProviderCapabilities.EMBED,
    }

    ALLOWED_HOSTS = re.compile(
        r"(?:[a-z0-9-]+\.)?(?:orionnet\.online|krk\.ru)", re.IGNORECASE
    )

    def normalize(self, raw: Dict[str, Any]) -> Camera:
        cid = str(raw.get("id") or raw.get("external_id") or "").strip()
        if not cid or not cid.isdigit():
            raise ValueError(f"Invalid Orion camera id: {cid}")
        title = str(raw.get("title") or f"Камера {cid}").strip()
        lat = raw.get("latitude")
        lon = raw.get("longitude")
        if lat is not None:
            lat = float(lat)
        if lon is not None:
            lon = float(lon)

        fluserver = str(raw.get("fluserver") or "fluserver.orionnet.online").strip()
        has_archive = bool(raw.get("flussonic_archive", 1))

        endpoints = [
            CameraEndpoint(
                kind="snapshot",
                url=f"http://{fluserver}/cam{cid}/preview.jpg",
                priority=100,
            ),
            CameraEndpoint(
                kind="hls",
                url=f"http://{fluserver}/cam{cid}/index.m3u8",
                priority=90,
            ),
            CameraEndpoint(
                kind="embed",
                url=f"http://{fluserver}/cam{cid}/embed.html?autoplay=true&dvr={'true' if has_archive else 'false'}",
                priority=80,
            ),
        ]

        # Extra endpoints passed in
        for ep in raw.get("endpoints") or []:
            k = str(ep.get("kind") or "")
            u = str(ep.get("url") or "")
            p = int(ep.get("priority") or 50)
            if k and u and self.validate_url(u):
                endpoints.append(CameraEndpoint(kind=k, url=u, priority=p))

        metadata = {
            "fluserver": fluserver,
            "flussonic_archive": int(has_archive),
            "marker": raw.get("marker", "."),
            "source": "cam.krk.ru",
        }

        return Camera(
            provider_id=self.provider_id,
            external_id=cid,
            title=title,
            address=title,
            camera_type="ORION",
            available=bool(raw.get("available", True)),
            latitude=lat,
            longitude=lon,
            endpoints=endpoints,
            metadata=metadata,
        )

    def validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "rtmp", "rtsp"}:
            return False
        hostname = parsed.hostname or ""
        return bool(self.ALLOWED_HOSTS.search(hostname))

    @staticmethod
    def fetch_public_cameras() -> List[Dict[str, Any]]:
        """Fetch all public cameras from http://cam.krk.ru/ rootScope."""
        req = urllib.request.Request(
            "http://cam.krk.ru/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        m = re.search(r"rootScope\s*=\s*(.*?);?\s*</script>", html, re.DOTALL)
        if not m:
            return []
        raw_json = m.group(1).strip()
        fixed = re.sub(r"'([^']*)'", r'"\1"', raw_json)
        data = json.loads(fixed)
        cameras = data.get("cameras", [])
        return cameras
