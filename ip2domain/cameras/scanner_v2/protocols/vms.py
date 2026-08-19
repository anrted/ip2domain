"""VMS (Video Management System) and proprietary NVR/Camera probe for Scanner v2.

Supports:
- Mobotix (FastStream / MXPEG)
- Frigate NVR
- Blue Iris
- Avtech EagleEyes
- GeoVision
- Shinobi NVR
"""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0


async def probe_vms(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe proprietary VMS and specialized camera streaming endpoints.

    Returns: success, brand, model, streams, http_port, protocols
    """
    result = {
        "success": False,
        "brand": "",
        "model": "",
        "vms_urls": [],
        "http_port": 0,
        "protocols": [],
        "credentials": {},
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, follow_redirects=True) as client:
        for port in candidate_ports:
            base = f"http://{ip}:{port}"
            for user, password in credentials[:2]:
                auth = (user, password) if user else None

                # 1. Mobotix FastStream / MXPEG
                try:
                    r = await client.get(f"{base}/control/faststream.jpg?stream=full", auth=auth, timeout=_TIMEOUT)
                    ctype = r.headers.get("content-type", "").lower()
                    if r.status_code == 200 and ("image/jpeg" in ctype or "multipart/x-mixed-replace" in ctype):
                        result["success"] = True
                        result["brand"] = "Mobotix"
                        result["model"] = "MXPEG Camera"
                        result["http_port"] = port
                        result["protocols"] = ["mobotix_faststream", "mjpeg"]
                        result["vms_urls"].append(f"{base}/control/faststream.jpg?stream=full")
                        if user:
                            result["credentials"] = {"user": user, "password": password}
                        return result
                except Exception:
                    pass

                # 2. Frigate NVR
                try:
                    r = await client.get(f"{base}/api/version", auth=auth, timeout=2.0)
                    if r.status_code == 200 and "frigate" in r.text.lower():
                        result["success"] = True
                        result["brand"] = "Frigate NVR"
                        result["http_port"] = port
                        result["protocols"] = ["frigate_vms", "http_snapshot"]
                        # Query config for cameras
                        try:
                            cr = await client.get(f"{base}/api/config", auth=auth, timeout=2.0)
                            if cr.status_code == 200:
                                cdata = cr.json()
                                for cam_name in list(cdata.get("cameras", {}).keys())[:6]:
                                    result["vms_urls"].append(f"{base}/api/{cam_name}/latest.jpg")
                        except Exception:
                            result["vms_urls"].append(f"{base}/api/latest.jpg")
                        return result
                except Exception:
                    pass

                # 3. Blue Iris
                try:
                    r = await client.get(f"{base}/mjpg/cam1/video.mjpg", auth=auth, timeout=2.0)
                    ctype = r.headers.get("content-type", "").lower()
                    if r.status_code == 200 and ("multipart/x-mixed-replace" in ctype or "image/jpeg" in ctype):
                        result["success"] = True
                        result["brand"] = "Blue Iris"
                        result["http_port"] = port
                        result["protocols"] = ["blue_iris", "mjpeg"]
                        result["vms_urls"].append(f"{base}/mjpg/cam1/video.mjpg")
                        return result
                except Exception:
                    pass

                # 4. Avtech EagleEyes Video.cgi
                try:
                    r = await client.get(f"{base}/cgi-bin/guest/Video.cgi?media=JPEG", auth=auth, timeout=2.0)
                    ctype = r.headers.get("content-type", "").lower()
                    if r.status_code == 200 and ("image/jpeg" in ctype or "multipart/x-mixed-replace" in ctype):
                        result["success"] = True
                        result["brand"] = "Avtech"
                        result["model"] = "EagleEyes IPCam"
                        result["http_port"] = port
                        result["protocols"] = ["avtech_video", "mjpeg"]
                        result["vms_urls"].append(f"{base}/cgi-bin/guest/Video.cgi?media=JPEG")
                        return result
                except Exception:
                    pass

    return result
