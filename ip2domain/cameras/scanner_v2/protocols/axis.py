"""Axis camera CGI probe for Camera Scanner v2."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

_AXIS_BRAND = "/axis-cgi/param.cgi?action=list&group=root.Brand"
_AXIS_NETWORK = "/axis-cgi/param.cgi?action=list&group=root.Network.eth0"
_AXIS_SNAPSHOT = "/axis-cgi/jpg/image.cgi"
_AXIS_MJPEG = "/axis-cgi/mjpg/video.cgi"


def _parse_axis_params(text: str) -> Dict[str, str]:
    params = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            params[k.strip()] = v.strip()
    return params


async def probe_axis(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe Axis camera CGI endpoints.

    Returns: brand, model, rtsp_urls, snapshot_url, mjpeg_url, http_port, credentials
    """
    result = {
        "success": False, "brand": "Axis", "model": "", "serial": "",
        "firmware": "", "rtsp_urls": [], "snapshot_url": "",
        "mjpeg_url": "", "http_port": 0, "credentials": {},
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        for port in candidate_ports:
            base = f"http://{ip}:{port}"
            for user, password in credentials:
                try:
                    auth = httpx.DigestAuth(user, password) if user else None
                    resp = await client.get(base + _AXIS_BRAND, auth=auth, timeout=_TIMEOUT)
                    if resp.status_code == 401 and user:
                        resp = await client.get(base + _AXIS_BRAND, auth=(user, password), timeout=_TIMEOUT)
                except Exception:
                    continue

                if resp.status_code == 401:
                    continue
                if resp.status_code != 200:
                    break


                text = resp.text
                params = _parse_axis_params(text)

                # Validate it's Axis
                brand_val = params.get("root.Brand.Brand", "")
                if "axis" not in brand_val.lower() and "AXIS" not in text:
                    break

                model = params.get("root.Brand.ProdShortName", "") or params.get("root.Brand.ProdNbr", "")
                creds_url = f"{user}:{password}@" if user else ""
                rtsp_urls = [
                    f"rtsp://{creds_url}{ip}/axis-media/media.amp",
                    f"rtsp://{creds_url}{ip}/axis-media/media.amp?videocodec=h264",
                ]

                result.update({
                    "success": True, "model": model, "http_port": port,
                    "credentials": {"user": user, "password": password},
                    "rtsp_urls": rtsp_urls,
                    "snapshot_url": base + _AXIS_SNAPSHOT,
                    "mjpeg_url": base + _AXIS_MJPEG,
                })
                return result

    return result
