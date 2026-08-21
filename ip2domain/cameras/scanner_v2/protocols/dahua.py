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
                try:
                    auth = httpx.DigestAuth(user, password) if user else None
                    resp = await client.get(base + _CGI_DEVICE_TYPE, auth=auth, timeout=_TIMEOUT)
                    if resp.status_code == 401 and user:
                        resp = await client.get(base + _CGI_DEVICE_TYPE, auth=(user, password), timeout=_TIMEOUT)
                except Exception:
                    continue

                if resp.status_code == 401:
                    continue
                if resp.status_code != 200:
                    break


                text = resp.text.strip()
                # Reject any HTML error or proxy/web pages (e.g. 503/404/login portals)
                if "<html" in text.lower() or "<!doctype" in text.lower() or "<body" in text.lower() or "<head" in text.lower():
                    break

                # Real Dahua CGI response is plain-text key-value: "type=IPC-HDW2831T-AS\r\n"
                lines = [l.strip() for l in text.splitlines() if "=" in l]
                type_lines = [l for l in lines if l.lower().startswith("type=") or l.lower().startswith("table.") or l.lower().startswith("app=")]
                if not type_lines:
                    break

                model = ""
                for line in type_lines:
                    k, v = line.split("=", 1)
                    if k.lower() == "type" or "name" in k.lower() or "type" in k.lower():
                        model = v.strip().strip('"\'')
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

                # Build RTSP & Snapshot URLs for Dahua
                creds_url = f"{user}:{password}@" if user else ""
                rtsp_urls = [
                    f"rtsp://{creds_url}{ip}:554/cam/realmonitor?channel=1&subtype=0",
                    f"rtsp://{creds_url}{ip}:554/cam/realmonitor?channel=1&subtype=1",
                ]
                result["rtsp_urls"] = rtsp_urls
                result["snapshot_url"] = f"{base}/cgi-bin/snapshot.cgi?channel=1"
                result["snapshot_urls"] = [
                    f"{base}/cgi-bin/snapshot.cgi?channel=1",
                    f"{base}/cgi-bin/snapshot.cgi?channel=0",
                    f"{base}/cgi-bin/snapshot.cgi",
                ]
                return result

    return result

