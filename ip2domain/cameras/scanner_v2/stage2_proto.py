"""Stage 2: Multi-protocol fingerprinting for Camera Scanner v2.

For each host with open ports:
  - Runs ONVIF, Hikvision, Dahua, Axis, RTSP, RTMP, HLS, generic HTTP probes in parallel
  - Merges results into a single CameraResult
  - Falls back to generic HTTP title/banner detection and port-based heuristics
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

import httpx

from .models import (
    CameraResult,
    StreamInfo,
    HTTP_PORTS,
    HTTPS_PORTS,
    RTSP_PORTS,
    RTMP_PORTS,
    ONVIF_PORTS,
    DVR_PORTS,
)
from .protocols.onvif import probe_onvif
from .protocols.hikvision import probe_hikvision
from .protocols.dahua import probe_dahua
from .protocols.axis import probe_axis
from .protocols.rtsp import probe_rtsp_direct
from .protocols.rtmp import probe_rtmp
from .protocols.hls import probe_hls_mjpeg
from .protocols.webrtc import probe_webrtc
from .protocols.vms import probe_vms
from .protocols.ingram import probe_ingram

logger = logging.getLogger(__name__)
_TIMEOUT = 3.5

# Generic HTTP camera keyword patterns
_CAMERA_BRANDS = {
    "hikvision": "Hikvision",
    "dahua": "Dahua",
    "axis": "Axis",
    "foscam": "Foscam",
    "amcrest": "Amcrest",
    "reolink": "Reolink",
    "hanwha": "Hanwha",
    "uniview": "Uniview",
    "unv": "Uniview",
    "cp plus": "CP Plus",
    "bosch": "Bosch",
    "pelco": "Pelco",
    "wisenet": "Hanwha",
    "xiongmai": "Xiongmai",
    "h264dvr": "Xiongmai",
    "netip": "Xiongmai",
    "tiandy": "Tiandy",
    "vivotek": "Vivotek",
    "mobotix": "Mobotix",
    "grandstream": "Grandstream",
    "nvr": "Generic NVR",
    "dvr": "Generic DVR",
    "ipcam": "Generic IPCam",
    "webcam": "Generic Webcam",
    "network camera": "Generic IPCam",
}


async def _probe_generic_http(
    ip: str,
    ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe HTTP title, Server header, WWW-Authenticate, and camera keyword detection."""
    result = {"success": False, "brand": "", "model": "", "title": "", "http_port": 0}
    if not ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=3.0, follow_redirects=True) as client:
        for port in ports[:4]:  # test max 4 HTTP ports
            for user, password in credentials[:2]:
                auth = (user, password) if user else None
                try:
                    resp = await client.get(f"http://{ip}:{port}/", auth=auth, timeout=3.0)
                    text = resp.text[:4096]
                    server = resp.headers.get("server", "")
                    www_auth = resp.headers.get("www-authenticate", "")
                    title_m = re.search(r"<title[^>]*>([^<]{1,128})</title>", text, re.IGNORECASE)
                    title = title_m.group(1).strip() if title_m else ""
                    combined = (title + " " + server + " " + www_auth + " " + text[:512]).lower()

                    brand = ""
                    for keyword, brand_name in _CAMERA_BRANDS.items():
                        if keyword in combined:
                            brand = brand_name
                            break

                    if brand or "rtsp" in combined or "stream" in combined or "camera" in combined or "video" in combined:
                        result.update({
                            "success": True,
                            "brand": brand or "Generic IPCam",
                            "title": title,
                            "http_port": port,
                        })
                        return result
                except Exception:
                    continue
    return result


async def probe_host_v2(
    ip: str,
    open_ports: List[int],
    credentials: List[Tuple[str, str]],
    protocols: Optional[List[str]] = None,
) -> Optional[CameraResult]:
    """Run protocol probes in parallel for a single host.

    Returns CameraResult if camera detected, None otherwise.
    """
    http_ports = sorted(set(open_ports) & (HTTP_PORTS | HTTPS_PORTS | DVR_PORTS))
    if not http_ports:
        http_ports = [p for p in open_ports if p not in RTSP_PORTS and p not in RTMP_PORTS]
    rtsp_ports = sorted(set(open_ports) & RTSP_PORTS)
    if not rtsp_ports and 554 in open_ports:
        rtsp_ports = [554]
    rtmp_ports = sorted(set(open_ports) & RTMP_PORTS)
    onvif_cands = sorted(set(open_ports) & (ONVIF_PORTS | HTTP_PORTS))

    active_protos = set(protocols) if protocols else {
        "onvif", "hikvision", "dahua", "axis", "rtsp", "hls", "rtmp", "webrtc", "vms"
    }

    probe_tasks = []
    task_keys = []

    if "onvif" in active_protos:
        probe_tasks.append(probe_onvif(ip, onvif_cands or http_ports, credentials))
        task_keys.append("onvif")
    if "hikvision" in active_protos:
        probe_tasks.append(probe_hikvision(ip, http_ports, credentials))
        task_keys.append("hikvision")
    if "dahua" in active_protos:
        probe_tasks.append(probe_dahua(ip, http_ports, credentials))
        task_keys.append("dahua")
    if "axis" in active_protos:
        probe_tasks.append(probe_axis(ip, http_ports, credentials))
        task_keys.append("axis")
    if "hls" in active_protos:
        probe_tasks.append(probe_hls_mjpeg(ip, http_ports, credentials))
        task_keys.append("hls")
    if "rtsp" in active_protos:
        probe_tasks.append(probe_rtsp_direct(ip, rtsp_ports or [554], credentials))
        task_keys.append("rtsp")
    if "rtmp" in active_protos and (rtmp_ports or 1935 in open_ports):
        probe_tasks.append(probe_rtmp(ip, rtmp_ports or [1935]))
        task_keys.append("rtmp")
    if "webrtc" in active_protos:
        probe_tasks.append(probe_webrtc(ip, http_ports, credentials))
        task_keys.append("webrtc")
    if "vms" in active_protos:
        probe_tasks.append(probe_vms(ip, http_ports, credentials))
        task_keys.append("vms")

    # Ingram fingerprinting always runs (independent of protocol filter)
    probe_tasks.append(probe_ingram(ip, http_ports, credentials))
    task_keys.append("ingram")

    probe_tasks.append(_probe_generic_http(ip, http_ports, credentials))
    task_keys.append("generic")

    results = await asyncio.gather(*probe_tasks, return_exceptions=True)
    res_map = {
        k: (r if isinstance(r, dict) else {})
        for k, r in zip(task_keys, results)
    }

    onvif_r = res_map.get("onvif", {})
    hik_r = res_map.get("hikvision", {})
    dahua_r = res_map.get("dahua", {})
    axis_r = res_map.get("axis", {})
    hls_r = res_map.get("hls", {})
    rtsp_r = res_map.get("rtsp", {})
    rtmp_r = res_map.get("rtmp", {})
    webrtc_r = res_map.get("webrtc", {})
    vms_r = res_map.get("vms", {})
    ingram_r = res_map.get("ingram", {})
    generic_r = res_map.get("generic", {})

    camera = CameraResult(ip=ip, open_ports=sorted(open_ports))
    detected = False

    # 1. ONVIF
    if onvif_r.get("success"):
        camera.brand = onvif_r.get("brand", "") or camera.brand
        camera.model = onvif_r.get("model", "") or camera.model
        camera.serial = onvif_r.get("serial", "") or camera.serial
        camera.firmware = onvif_r.get("firmware", "") or camera.firmware
        camera.onvif_port = onvif_r.get("onvif_port", 0)
        camera.credentials = onvif_r.get("credentials", {})
        camera.protocols.append("onvif")
        for url in onvif_r.get("rtsp_urls", []):
            camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 2. Hikvision ISAPI
    if hik_r.get("success"):
        camera.brand = camera.brand or "Hikvision"
        camera.model = camera.model or hik_r.get("model", "")
        camera.serial = camera.serial or hik_r.get("serial", "")
        camera.http_port = camera.http_port or hik_r.get("http_port", 0)
        camera.credentials = camera.credentials or hik_r.get("credentials", {})
        camera.protocols.append("hikvision_isapi")
        for url in hik_r.get("rtsp_urls", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 3. Dahua CGI
    if dahua_r.get("success"):
        camera.brand = camera.brand or "Dahua"
        camera.model = camera.model or dahua_r.get("model", "")
        camera.http_port = camera.http_port or dahua_r.get("http_port", 0)
        camera.credentials = camera.credentials or dahua_r.get("credentials", {})
        camera.protocols.append("dahua_cgi")
        for url in dahua_r.get("rtsp_urls", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 4. Axis CGI
    if axis_r.get("success"):
        camera.brand = camera.brand or "Axis"
        camera.model = camera.model or axis_r.get("model", "")
        camera.http_port = camera.http_port or axis_r.get("http_port", 0)
        camera.credentials = camera.credentials or axis_r.get("credentials", {})
        camera.protocols.append("axis_cgi")
        for url in axis_r.get("rtsp_urls", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        if axis_r.get("mjpeg_url"):
            camera.streams.append(StreamInfo(url=axis_r["mjpeg_url"], stream_type="mjpeg"))
        detected = True

    # 5. HLS / MJPEG / HTTP Snapshot
    if hls_r.get("success"):
        camera.protocols.append("http_snapshot")
        camera.http_port = camera.http_port or hls_r.get("http_port", 0)
        camera.credentials = camera.credentials or hls_r.get("credentials", {})
        if hls_r.get("snapshot_url"):
            camera.streams.append(StreamInfo(url=hls_r["snapshot_url"], stream_type="http_snapshot", verified=True))
        if hls_r.get("hls_url"):
            camera.streams.append(StreamInfo(url=hls_r["hls_url"], stream_type="hls"))
            camera.protocols.append("hls")
        if hls_r.get("mjpeg_url"):
            camera.streams.append(StreamInfo(url=hls_r["mjpeg_url"], stream_type="mjpeg"))
        detected = True

    # 6. RTSP Direct
    if rtsp_r.get("success"):
        camera.rtsp_port = rtsp_r.get("open_port", 554)
        camera.brand = camera.brand or rtsp_r.get("brand", "") or "Generic RTSP"
        camera.credentials = camera.credentials or rtsp_r.get("credentials", {})
        camera.protocols.append("rtsp_direct")
        for url in rtsp_r.get("rtsp_urls", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 7. RTMP
    if rtmp_r.get("success"):
        camera.rtmp_port = rtmp_r.get("open_port", 1935)
        camera.protocols.append("rtmp")
        for url in rtmp_r.get("rtmp_urls", [rtmp_r.get("rtmp_url", "")]):
            if url and not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtmp"))
        detected = True

    # 8. WebRTC / WHEP
    if webrtc_r.get("success"):
        camera.brand = camera.brand or webrtc_r.get("brand", "WebRTC Camera")
        camera.http_port = camera.http_port or webrtc_r.get("http_port", 0)
        for p in webrtc_r.get("protocols", []):
            if p not in camera.protocols:
                camera.protocols.append(p)
        for url in webrtc_r.get("webrtc_urls", []):
            if not any(s.url == url for s in camera.streams):
                stype = "whep" if "whep" in url else "webrtc"
                camera.streams.append(StreamInfo(url=url, stream_type=stype, verified=True))
        detected = True

    # 9. VMS / Mobotix / Frigate / Blue Iris / Avtech
    if vms_r.get("success"):
        camera.brand = vms_r.get("brand", "") or camera.brand
        camera.model = vms_r.get("model", "") or camera.model
        camera.http_port = camera.http_port or vms_r.get("http_port", 0)
        camera.credentials = camera.credentials or vms_r.get("credentials", {})
        for p in vms_r.get("protocols", []):
            if p not in camera.protocols:
                camera.protocols.append(p)
        for url in vms_r.get("vms_urls", []):
            if not any(s.url == url for s in camera.streams):
                stype = "mjpeg" if ("mjpg" in url or "Video.cgi" in url or "faststream" in url) else "http_snapshot"
                camera.streams.append(StreamInfo(url=url, stream_type=stype, verified=True))
        detected = True

    # 10. Ingram fingerprint (brand detection + brand-specific snapshot/stream)
    if ingram_r.get("success"):
        camera.brand = camera.brand or ingram_r.get("brand", "")
        camera.http_port = camera.http_port or ingram_r.get("http_port", 0)
        for p in ingram_r.get("protocols", []):
            if p not in camera.protocols:
                camera.protocols.append(p)
        for s in ingram_r.get("streams", []):
            url = s.get("url", "")
            stype = s.get("type", "http_snapshot")
            if url and not any(st.url == url for st in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type=stype, verified=True))
        detected = True

    # 11. Generic HTTP fallback (only if HTTP returned working snapshot/stream)
    if not detected and generic_r.get("success"):
        camera.brand = generic_r.get("brand", "Generic IPCam")
        camera.http_port = generic_r.get("http_port", 0)
        camera.protocols.append("http_generic")
        detected = True

    if not detected or not camera.streams:
        # Discard hosts that returned 401 Unauthorized or have 0 working streams
        return None

    # Default brand if still empty
    if not camera.brand:
        camera.brand = "Unknown Camera"

    # Set primary ports from open_ports if not set
    if not camera.http_port:
        for p in open_ports:
            if p in HTTP_PORTS:
                camera.http_port = p
                break
    if not camera.rtsp_port:
        for p in open_ports:
            if p in RTSP_PORTS or p == 554:
                camera.rtsp_port = p
                break

    return camera
