"""Dahua CGI HTTP probe for Camera Scanner v2."""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

_CGI_DEVICE_TYPE = "/cgi-bin/magicBox.cgi?action=getDeviceType"
_CGI_SERIAL = "/cgi-bin/magicBox.cgi?action=getSerialNo"
_CGI_VERSION = "/cgi-bin/magicBox.cgi?action=getSoftwareVersion"
_CGI_SNAPSHOT = "/cgi-bin/snapshot.cgi?channel=0"
_CGI_MJPEG = "/cgi-bin/mjpg/video.cgi?channel=0"


async def probe_dahua(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe Dahua CGI endpoints.

    Returns: brand, model, serial, firmware, rtsp_urls, snapshot_url, http_port, credentials
    """
    result = {
        "success": False, "brand": "Dahua", "model": "", "serial": "",
        "firmware": "", "rtsp_urls": [], "snapshot_url": "",
        "http_port": 0, "credentials": {},
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        for port in candidate_ports:
            base = f"http://{ip}:{port}"
            for user, password in credentials:
                auth = (user, password) if user else None
                try:
                    resp = await client.get(base + _CGI_DEVICE_TYPE, auth=auth, timeout=_TIMEOUT)
                except Exception:
                    continue

                if resp.status_code == 401:
                    continue
                if resp.status_code != 200:
                    break

                text = resp.text.strip()
                # Dahua CGI returns: "type=IPC-HDW2831T-AS\r\n"
                if "=" not in text and "type" not in text.lower():
                    break

                model = ""
                for line in text.splitlines():
                    if "=" in line:
                        model = line.split("=", 1)[1].strip()
                        break

                serial = ""
                firmware = ""
                try:
                    sr = await client.get(base + _CGI_SERIAL, auth=auth, timeout=_TIMEOUT)
                    if sr.status_code == 200:
                        for line in sr.text.splitlines():
                            if "=" in line:
                                serial = line.split("=", 1)[1].strip()
                                break
                    vr = await client.get(base + _CGI_VERSION, auth=auth, timeout=_TIMEOUT)
                    if vr.status_code == 200:
                        for line in vr.text.splitlines():
                            if "=" in line:
                                firmware = line.split("=", 1)[1].strip()
                                break
                except Exception:
                    pass

                result.update({
                    "success": True, "model": model, "serial": serial,
                    "firmware": firmware, "http_port": port,
                    "credentials": {"user": user, "password": password},
                })

                # Build RTSP URLs for Dahua
                creds_url = f"{user}:{password}@" if user else ""
                rtsp_urls = [
                    f"rtsp://{creds_url}{ip}:554/cam/realmonitor?channel=1&subtype=0",
                    f"rtsp://{creds_url}{ip}:554/cam/realmonitor?channel=1&subtype=1",
                ]
                result["rtsp_urls"] = rtsp_urls
                result["snapshot_url"] = base + _CGI_SNAPSHOT
                return result

    return result
