"""Goodline A42 Road Cameras provider for Kuzbass (Novokuznetsk, Kemerovo, etc.).

Retrieves public road cameras from pdd.a42.ru.
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


class A42Provider(CameraProvider):
    provider_id = "a42"
    display_name = "Goodline A42 (Дорожные камеры)"
    capabilities = {
        ProviderCapabilities.DISCOVERY,
        ProviderCapabilities.STREAM,
    }

    ALLOWED_HOSTS = re.compile(
        r"(?:[a-z0-9-]+\.)?(?:goodline\.info|a42\.ru)", re.IGNORECASE
    )

    def normalize(self, raw: Dict[str, Any]) -> Camera:
        cid = str(raw.get("id") or raw.get("external_id") or "").strip()
        if not cid:
            raise ValueError(f"Invalid A42 camera id: {cid}")
        title = str(raw.get("title") or f"Камера {cid}").strip()
        address = str(raw.get("address") or title).strip()
        city = str(raw.get("city") or "").strip()

        coords = raw.get("coordinates") or [None, None]
        lat = float(coords[0]) if len(coords) > 0 and coords[0] is not None else None
        lon = float(coords[1]) if len(coords) > 1 and coords[1] is not None else None

        sldp = str(raw.get("sldp") or "").strip()
        endpoints = []
        if sldp:
            endpoints.append(
                CameraEndpoint(
                    kind="rtsp",
                    url=sldp,
                    priority=100,
                    metadata={"protocol": "sldp"},
                )
            )

        metadata = {
            "city": city,
            "archive_stream_id": raw.get("archive_stream_id"),
            "archive_depth": raw.get("archive_depth"),
            "source": "pdd.a42.ru",
        }

        return Camera(
            provider_id=self.provider_id,
            external_id=cid,
            title=title,
            address=address,
            camera_type="A42",
            available=bool(raw.get("available", True)),
            latitude=lat,
            longitude=lon,
            endpoints=endpoints,
            metadata=metadata,
        )

    def validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "ws", "wss", "rtsp"}:
            return False
        hostname = parsed.hostname or ""
        return bool(self.ALLOWED_HOSTS.search(hostname))

    @staticmethod
    def fetch_public_cameras() -> List[Dict[str, Any]]:
        """Fetch all public Kuzbass cameras from pdd.a42.ru."""
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        req1 = urllib.request.Request(
            "https://pdd.a42.ru/camera/novokuznetsk",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with opener.open(req1, timeout=6) as resp1:
            html = resp1.read().decode("utf-8", errors="ignore")

        m_cam = re.search(r'name="camera-token"\s+content="([^"]+)"', html)
        m_csrf = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
        if not m_cam:
            return []

        cam_token = m_cam.group(1)
        csrf_token = m_csrf.group(1) if m_csrf else ""

        req2 = urllib.request.Request(
            "https://pdd.a42.ru/ajax/cameras",
            data=b"",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "X-Requested-With": "XMLHttpRequest",
                "X-CAMERA-TOKEN": cam_token,
                "X-CSRF-TOKEN": csrf_token,
                "Referer": "https://pdd.a42.ru/camera/novokuznetsk",
            },
        )
        with opener.open(req2, timeout=6) as resp2:
            data = json.loads(resp2.read().decode())

        cameras = []
        for city_info in data.get("citiesCameras", []):
            city_name = city_info.get("city", "")
            for cam in city_info.get("cameras", []):
                cam_copy = dict(cam)
                cam_copy.setdefault("city", city_name)
                cameras.append(cam_copy)
        return cameras
