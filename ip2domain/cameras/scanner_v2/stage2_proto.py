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
from .protocols.sofia import probe_sofia
from .protocols.dahua_media import probe_dahua_media

logger = logging.getLogger(__name__)
_TIMEOUT = 3.5

# Generic HTTP camera keyword patterns
_CAMERA_BRANDS = {
    "hikvision": "Hikvision",
    "hiwatch": "Hikvision",
    "ezviz": "Hikvision",
    "hilook": "Hikvision",
    "dahua": "Dahua",
    "imou": "Dahua",
    "lorex": "Dahua",
    "axis": "Axis",
    "foscam": "Foscam",
    "amcrest": "Amcrest",
    "reolink": "Reolink",
    "hanwha": "Hanwha",
    "wisenet": "Hanwha",
    "samsung": "Hanwha",
    "uniview": "Uniview",
    "unv": "Uniview",
    "topsvision": "Topsvision",
    "topsee": "Topsvision",
    "jovision": "Jovision",
    "xiongmai": "Xiongmai",
    "h264dvr": "Xiongmai",
    "netip": "Xiongmai",
    "netsurveillance": "Xiongmai",
    "cp plus": "CP Plus",
    "bosch": "Bosch",
    "pelco": "Pelco",
    "tiandy": "Tiandy",
    "vivotek": "Vivotek",
    "mobotix": "Mobotix",
    "grandstream": "Grandstream",
    "beward": "Beward",
    "trassir": "Trassir",
    "activecam": "ActiveCam",
    "polyvision": "Polyvision",
    "rvi": "RVi",
    "novicam": "Novicam",
    "ltv": "LTV",
    "milesight": "Milesight",
    "tvt": "TVT",
    "sunell": "Sunell",
    "avigilon": "Avigilon",
    "flir": "FLIR",
    "ubiquiti": "Ubiquiti UniFi",
    "unifi video": "Ubiquiti UniFi",
    "tapo": "TP-Link Tapo",
    "vstarcam": "VStarcam",
    "sricam": "Sricam",
    "srihome": "SriHome",
    "nvr": "Generic NVR",
    "dvr": "Generic DVR",
    "ipcam": "Generic IPCam",
    "ip camera": "Generic IPCam",
    "ip_camera": "Generic IPCam",
    "webcam": "Generic Webcam",
    "network camera": "Generic IPCam",
    "surveillance": "Generic Surveillance",
    "video server": "Generic Video Server",
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
    # Only add 554 if it was actually found open by masscan
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
    if "rtsp" in active_protos and rtsp_ports:  # Only probe RTSP if a RTSP port was actually found open
        probe_tasks.append(probe_rtsp_direct(ip, rtsp_ports, credentials))
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

    # Sofia / Xiongmai (port 34567)
    if 34567 in open_ports or "sofia" in active_protos or "xiongmai" in active_protos:
        probe_tasks.append(probe_sofia(ip, 34567, credentials))
        task_keys.append("sofia")

    # Dahua Media (port 37777)
    if 37777 in open_ports or "dahua" in active_protos or "dhip" in active_protos:
        probe_tasks.append(probe_dahua_media(ip, 37777, credentials))
        task_keys.append("dahua_media")

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
    sofia_r = res_map.get("sofia", {})
    dahua_media_r = res_map.get("dahua_media", {})
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
        if onvif_r.get("snapshot_url"):
            camera.streams.append(StreamInfo(url=onvif_r["snapshot_url"], stream_type="http_snapshot"))
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
        if hik_r.get("snapshot_url"):
            camera.streams.append(StreamInfo(url=hik_r["snapshot_url"], stream_type="http_snapshot"))
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
        for snap_url in dahua_r.get("snapshot_urls", [dahua_r.get("snapshot_url")]):
            if snap_url and not any(s.url == snap_url for s in camera.streams):
                camera.streams.append(StreamInfo(url=snap_url, stream_type="http_snapshot"))
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
        if axis_r.get("snapshot_url"):
            camera.streams.append(StreamInfo(url=axis_r["snapshot_url"], stream_type="http_snapshot"))
        if axis_r.get("mjpeg_url"):
            camera.streams.append(StreamInfo(url=axis_r["mjpeg_url"], stream_type="mjpeg"))
        detected = True


    # 5. HLS / MJPEG / HTTP Snapshot
    if hls_r.get("success"):
        camera.protocols.append("http_snapshot")
        camera.http_port = camera.http_port or hls_r.get("http_port", 0)
        camera.credentials = camera.credentials or hls_r.get("credentials", {})
        if hls_r.get("snapshot_url"):
            camera.streams.append(StreamInfo(url=hls_r["snapshot_url"], stream_type="http_snapshot"))
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
                if url.startswith("rtsp://"):
                    stype = "rtsp"
                elif "whep" in url:
                    stype = "whep"
                else:
                    stype = "webrtc"
                camera.streams.append(StreamInfo(url=url, stream_type=stype))
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
                camera.streams.append(StreamInfo(url=url, stream_type=stype))
        detected = True

    # 10. Sofia / Xiongmai (NETSurveillance port 34567)
    if sofia_r.get("success"):
        camera.brand = camera.brand or "Xiongmai"
        camera.model = sofia_r.get("model", "") or camera.model or "Xiongmai NVR"
        camera.serial = sofia_r.get("serial", "") or camera.serial
        camera.firmware = sofia_r.get("firmware", "") or camera.firmware
        camera.rtsp_port = camera.rtsp_port or sofia_r.get("rtsp_port", 554)
        camera.http_port = camera.http_port or sofia_r.get("http_port", 80)
        camera.credentials = camera.credentials or sofia_r.get("credentials", {})
        if "xiongmai_sofia" not in camera.protocols:
            camera.protocols.append("xiongmai_sofia")
        for url in sofia_r.get("streams", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 11. Dahua Media (DHIP port 37777)
    if dahua_media_r.get("success"):
        camera.brand = camera.brand or "Dahua"
        camera.model = camera.model or dahua_media_r.get("model", "Dahua DVR/NVR")
        camera.credentials = camera.credentials or dahua_media_r.get("credentials", {})
        if "dahua_dhip" not in camera.protocols:
            camera.protocols.append("dahua_dhip")
        for url in dahua_media_r.get("streams", []):
            if not any(s.url == url for s in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type="rtsp"))
        detected = True

    # 12. Ingram fingerprint (brand detection + brand-specific snapshot/stream)
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
                camera.streams.append(StreamInfo(url=url, stream_type=stype))
        detected = True


    # 11. Generic HTTP fallback (only if HTTP returned working snapshot/stream)
    if not detected and generic_r.get("success"):
        camera.brand = generic_r.get("brand", "Generic IPCam")
        camera.http_port = generic_r.get("http_port", 0)
        camera.protocols.append("http_generic")
        detected = True
        # Build fallback stream URLs for generic cameras:
        # Try RTSP on open RTSP ports
        for p in open_ports:
            if p in RTSP_PORTS or p == 554:
                url = f"rtsp://{ip}:{p}/"
                if not any(s.url == url for s in camera.streams):
                    from .models import StreamInfo as _SI
                    camera.streams.append(_SI(url=url, stream_type="rtsp"))
                break
        # Try HTTP snapshot candidates on the detected HTTP port
        if generic_r.get("http_port"):
            hp = generic_r['http_port']
            base_g = f"http://{ip}:{hp}"
            candidates = [
                f"{base_g}/snap.jpg?JpegCam=0",
                f"{base_g}/cgi-bin/snapshot.cgi?channel=1",
                f"{base_g}/snapshot.jpg",
                f"{base_g}/image.jpg",
            ]
            for c_url in candidates:
                if not any(s.url == c_url for s in camera.streams):
                    camera.streams.append(StreamInfo(url=c_url, stream_type="http_snapshot"))


    if not detected:
        # Not a camera at all — discard
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

    # If still no streams at all, build a generic RTSP fallback so the camera isn't discarded
    if not camera.streams:
        for p in open_ports:
            if p in RTSP_PORTS or p == 554:
                from .models import StreamInfo as _SI3
                camera.streams.append(_SI3(url=f"rtsp://{ip}:{p}/", stream_type="rtsp"))
                camera.rtsp_port = camera.rtsp_port or p
                break

    return camera
