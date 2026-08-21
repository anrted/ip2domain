"""Hikvision ISAPI HTTP probe for Camera Scanner v2."""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

_ISAPI_DEVICE_INFO = "/ISAPI/System/deviceInfo"
_ISAPI_CHANNELS = "/ISAPI/Streaming/channels"
_ISAPI_SNAPSHOT = "/ISAPI/Streaming/channels/101/picture"


def _parse_xml_tag(xml: str, tag: str) -> str:
    m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xml, re.IGNORECASE)
    return m.group(1).strip() if m else ""


async def probe_hikvision(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe Hikvision ISAPI endpoints on candidate HTTP ports.

    Returns: brand, model, serial, firmware, rtsp_urls, snapshot_url, http_port, credentials
    """
    result = {
        "success": False, "brand": "Hikvision", "model": "", "serial": "",
        "firmware": "", "rtsp_urls": [], "snapshot_url": "",
        "http_port": 0, "credentials": {},
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        for port in candidate_ports:
            base = f"http://{ip}:{port}"
            for user, password in credentials:
                try:
                    auth = httpx.DigestAuth(user, password) if user else None
                    resp = await client.get(
                        base + _ISAPI_DEVICE_INFO,
                        auth=auth,
                        timeout=_TIMEOUT,
                    )
                    if resp.status_code == 401 and user:
                        resp = await client.get(
                            base + _ISAPI_DEVICE_INFO,
                            auth=(user, password),
                            timeout=_TIMEOUT,
                        )
                except Exception:
                    continue

                if resp.status_code == 401:
                    # Wrong credentials, try next pair
                    continue
                if resp.status_code != 200:
                    break  # Port likely not Hikvision ISAPI


                xml = resp.text
                # Verify it's actually ISAPI
                if "deviceName" not in xml and "DeviceInfo" not in xml:
                    break

                model = _parse_xml_tag(xml, "model") or _parse_xml_tag(xml, "deviceName")
                serial = _parse_xml_tag(xml, "serialNumber")
                firmware = _parse_xml_tag(xml, "firmwareVersion")

                result.update({
                    "success": True, "model": model, "serial": serial,
                    "firmware": firmware, "http_port": port,
                    "credentials": {"user": user, "password": password},
                })

                # Get streaming channels
                rtsp_urls = []
                try:
                    ch_resp = await client.get(base + _ISAPI_CHANNELS, auth=auth, timeout=_TIMEOUT)
                    if ch_resp.status_code == 200:
                        ids = re.findall(r"<id>(\d+)</id>", ch_resp.text)
                        for ch_id in ids[:8]:  # max 8 channels
                            rtsp_urls.append(f"rtsp://{ip}:554/Streaming/Channels/{ch_id}")
                except Exception:
                    pass

                # Fallback: standard channels 101-108
                if not rtsp_urls:
                    rtsp_urls = [
                        f"rtsp://{ip}:554/Streaming/Channels/101",
                        f"rtsp://{ip}:554/Streaming/Channels/201",
                    ]

                result["rtsp_urls"] = rtsp_urls
                result["snapshot_url"] = base + _ISAPI_SNAPSHOT
                return result

    return result


async def probe_hikvision_snapshot(ip: str, port: int, credentials: Tuple[str, str]) -> Optional[bytes]:
    """Try to fetch a JPEG snapshot via ISAPI."""
    user, password = credentials
    auth = (user, password) if user else None
    url = f"http://{ip}:{port}{_ISAPI_SNAPSHOT}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(url, auth=auth)
            if resp.status_code == 200 and resp.content[:3] == b"\xff\xd8\xff":
                return resp.content
    except Exception:
        pass
    return None
