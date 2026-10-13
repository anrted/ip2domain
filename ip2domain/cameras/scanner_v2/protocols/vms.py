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

                # 5. DevLine («Линия») Video Surveillance VMS
                try:
                    r = await client.get(f"{base}/", auth=auth, timeout=2.5)
                    server_hdr = r.headers.get("server", "").lower()
                    text_l = r.text[:2048].lower()
                    if "devline" in server_hdr or "devline" in text_l or "linia server" in server_hdr:
                        result["success"] = True
                        result["brand"] = "DevLine"
                        result["model"] = "DevLine Линия (NVR/VMS)"
                        result["http_port"] = port
                        result["protocols"] = ["devline_vms", "http_snapshot", "hls"]
                        # Generate snapshot and HLS URLs for channels 0..3
                        for ch in range(4):
                            result["vms_urls"].append(f"{base}/cameras/{ch}/image")
                            result["vms_urls"].append(f"{base}/cameras/{ch}/streaming/sub.m3u8")
                        if user and r.status_code == 200:
                            result["credentials"] = {"user": user, "password": password}
                        return result
                except Exception:
                    pass

                # 6. Macroscop VMS (Russian enterprise IP surveillance)
                try:
                    # Probe root or /configex
                    r_mac = await client.get(f"{base}/configex", auth=auth, timeout=2.5)
                    if r_mac.status_code == 404:
                        r_mac = await client.get(f"{base}/", auth=auth, timeout=2.0)
                    server_hdr = r_mac.headers.get("server", "").lower()
                    mac_text = r_mac.text[:4096].lower()
                    if (
                        "macroscop" in server_hdr
                        or "macroscop" in mac_text
                        or "макроскоп" in mac_text
                        or "<channels>" in mac_text
                        or "<channel id=" in mac_text
                    ):
                        result["success"] = True
                        result["brand"] = "Macroscop"
                        result["model"] = "Macroscop VMS Server"
                        result["http_port"] = port
                        result["protocols"] = ["macroscop_vms", "http_snapshot", "mjpeg"]
                        # Extract channel UUIDs if present in config XML
                        import re as _re
                        chan_ids = _re.findall(r'Id="([a-f0-9\-]{16,40})"', r_mac.text, _re.IGNORECASE)
                        for cid in chan_ids[:6]:
                            result["vms_urls"].append(f"{base}/image?channelid={cid}")
                            result["vms_urls"].append(f"{base}/mjpeg?channelid={cid}")
                        # Fallback standard channel index URLs
                        if not result["vms_urls"]:
                            for ch in range(4):
                                result["vms_urls"].append(f"{base}/image?channelid={ch}")
                                result["vms_urls"].append(f"{base}/command?cmd=getimage&channelid={ch}")
                        if user and r_mac.status_code == 200:
                            result["credentials"] = {"user": user, "password": password}
                        return result
                except Exception:
                    pass

                # 7. Trassir VMS (DSSL Russian surveillance system)
                try:
                    r_trs = await client.get(f"{base}/", auth=auth, timeout=2.5)
                    s_trs = r_trs.headers.get("server", "").lower()
                    t_trs = r_trs.text[:2048].lower()
                    if "trassir" in s_trs or "trassir" in t_trs or "dssl" in t_trs:
                        result["success"] = True
                        result["brand"] = "Trassir"
                        result["model"] = "Trassir NVR/VMS"
                        result["http_port"] = port
                        result["protocols"] = ["trassir_vms", "http_snapshot", "mjpeg"]
                        for ch in range(4):
                            result["vms_urls"].append(f"{base}/screenshot/{ch}")
                            result["vms_urls"].append(f"{base}/video/{ch}?container=mjpeg")
                            result["vms_urls"].append(f"{base}/get_stream?channel={ch}&container=mjpeg")
                        if user and r_trs.status_code == 200:
                            result["credentials"] = {"user": user, "password": password}
                        return result
                except Exception:
                    pass

                # 8. TVT / RaySharp Web NVR snapshot probing
                try:
                    for snap_p in (
                        "/cgi-bin/snapshot.cgi?channel=1",
                        "/cgi-bin/snapshot.cgi?chn=0",
                        "/ccm/ccm_pic_get.js?h=0&channel=0",
                    ):
                        r_snap = await client.get(f"{base}{snap_p}", auth=auth, timeout=2.0)
                        ctype = r_snap.headers.get("content-type", "").lower()
                        if r_snap.status_code == 200 and "image/jpeg" in ctype:
                            result["success"] = True
                            brand_val = "RaySharp" if "chn=" in snap_p else "TVT"
                            result["brand"] = brand_val
                            result["model"] = f"{brand_val} DVR/NVR"
                            result["http_port"] = port
                            result["protocols"] = [f"{brand_val.lower()}_media", "http_snapshot"]
                            result["vms_urls"].append(f"{base}{snap_p}")
                            if user:
                                result["credentials"] = {"user": user, "password": password}
                            return result
                except Exception:
                    pass

    return result
