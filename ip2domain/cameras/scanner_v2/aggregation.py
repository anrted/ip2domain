"""Pure legacy camera projection; precedence and fallbacks are API compatibility policy.

No network I/O. New non-camera plugins must use HostObservation instead.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .models import CameraResult, StreamInfo, HTTP_PORTS, RTSP_PORTS
from .protocols.rtsp import (
    _get_brand_rtsp_paths,
    _HIK_PATHS,
    _DAHUA_PATHS,
    _XM_PATHS,
    _AXIS_PATHS,
    _UNV_PATHS,
    _REOLINK_PATHS,
    _BEWARD_PATHS,
    _SAMSUNG_PATHS,
    _GENERIC_PATHS,
)
from .protocols.rtmp import _RTMP_PATHS

_KNOWN_CAMERA_BRAND_SUBSTRINGS = (
    "hikvision", "hiwatch", "dahua", "axis", "reolink", "trassir", "xiongmai", "flussonic",
    "streamer", "dnvrs", "rvi", "uniview", "unv", "tiandy", "mobotix", "generic nvr", "generic dvr",
    "generic ipcam", "generic webcam", "generic surveillance", "generic video server", "generic rtsp",
    "unknown camera", "tp-link", "ezviz", "hilook", "imou", "lorex", "foscam", "amcrest", "hanwha",
    "wisenet", "samsung", "topsvision", "topsee", "jovision", "h264", "netip", "netsurveillance",
    "cp plus", "bosch", "pelco", "vivotek", "grandstream", "beward", "activecam", "polyvision",
    "novicam", "ltv", "milesight", "tvt", "sunell", "avigilon", "flir", "ubiquiti unifi", "tapo",
    "tl-sc", "vstarcam", "sricam", "srihome", "herospeed", "onvif",
)

def _is_camera_brand(brand: str) -> bool:
    if not brand:
        return False
    b = brand.lower()
    return any(p in b for p in _KNOWN_CAMERA_BRAND_SUBSTRINGS)


def merge_host_cameras(cameras: List[CameraResult]) -> Optional[CameraResult]:
    """Keep all endpoint identities and distinct stream URLs for one host."""
    if not cameras:
        return None
    from dataclasses import replace
    from urllib.parse import urlsplit
    host = CameraResult(ip=cameras[0].ip)
    streams = {}
    endpoints = {}
    for camera in cameras:
        if camera.ip != host.ip:
            raise ValueError("Cannot merge different hosts")
        for key in ("brand", "model", "serial", "firmware", "city", "region", "country_code", "isp", "timestamp", "device_category", "web_title", "web_url", "web_screenshot"):
            if not getattr(host, key):
                setattr(host, key, getattr(camera, key))
        for key in ("http_port", "rtsp_port", "rtmp_port", "onvif_port"):
            if not getattr(host, key):
                setattr(host, key, getattr(camera, key))
        host.open_ports = sorted(set(host.open_ports + camera.open_ports))
        host.protocols = list(dict.fromkeys(host.protocols + camera.protocols))
        source_port = camera.onvif_port or camera.http_port or camera.rtsp_port or camera.rtmp_port
        descriptions = camera.endpoints or [{
            "port": p or source_port, "brand": camera.brand, "model": camera.model,
            "serial": camera.serial, "protocols": camera.protocols,
            "auth_required": camera.auth_required,
        } for p in (camera.open_ports or [source_port])]
        for endpoint in descriptions:
            key = (endpoint.get("port"), endpoint.get("serial"), tuple(endpoint.get("protocols", [])))
            endpoints[key] = endpoint
        for stream in camera.streams:
            parsed = urlsplit(stream.url)
            item = replace(stream)
            item.source_port = item.source_port or source_port or parsed.port or 0
            if item.credentials is None:
                item.credentials = dict(camera.credentials)
            previous = streams.get(item.url)
            if previous is None or (item.verified and not previous.verified):
                streams[item.url] = item
    host.streams = list(streams.values())
    host.endpoints = list(endpoints.values())
    # Credentials belong to their endpoint, never to all cameras behind an IP.
    host.credentials = dict(cameras[0].credentials) if len(cameras) == 1 else {}
    host.auth_required = True if any(c.auth_required is True for c in cameras) else None
    return host


def merge_camera_results(
    ip: str, open_ports: List[int], res_map: Dict[str, Dict],
) -> Optional[CameraResult]:
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


    # 13. SpRecord Audio Recording System
    sprecord_r = res_map.get("sprecord", {})
    if sprecord_r.get("success"):
        camera.brand = "SpRecord"
        camera.model = sprecord_r.get("model", "Система записи разговоров SpRecord")
        camera.firmware = sprecord_r.get("firmware", "") or camera.firmware
        camera.http_port = sprecord_r.get("http_port", 0) or camera.http_port
        camera.credentials = camera.credentials or sprecord_r.get("credentials", {})
        camera.auth_required = sprecord_r.get("auth_required", False)
        if "sprecord_audio" not in camera.protocols:
            camera.protocols.append("sprecord_audio")
        for s in sprecord_r.get("streams", []):
            url = s.get("url", "")
            stype = s.get("type", "http_audio")
            if url and not any(st.url == url for st in camera.streams):
                camera.streams.append(StreamInfo(url=url, stream_type=stype))
        detected = True

    # 13. Router / Gateway detection
    router_r = res_map.get("router", {})
    if router_r.get("success"):
        camera.brand = camera.brand or router_r.get("brand", "Generic Router")
        camera.model = camera.model or router_r.get("model", "")
        camera.device_category = "router"
        camera.http_port = camera.http_port or router_r.get("web_port", 0)
        camera.web_title = camera.web_title or router_r.get("title", "")
        camera.web_url = camera.web_url or router_r.get("web_url", "")
        if router_r.get("auth_required") is not None:
            camera.auth_required = router_r.get("auth_required")
        for p in router_r.get("protocols", []):
            if p not in camera.protocols:
                camera.protocols.append(p)
        detected = True

    # 14. Generic HTTP fallback (only if HTTP returned working snapshot/stream/panel)
    if generic_r.get("success"):
        if not detected:
            camera.brand = generic_r.get("brand", "Generic Web Device")
            camera.model = generic_r.get("model", "")
            camera.device_category = generic_r.get("device_category", "generic_web")
            camera.http_port = generic_r.get("http_port", 0)
            camera.web_title = generic_r.get("title", "")
            camera.web_url = generic_r.get("web_url", "")
            camera.protocols.append("http_generic")
            detected = True
            # Try RTSP on dedicated RTSP ports only
            for p in open_ports:
                if p in RTSP_PORTS or p == 554:
                    url = f"rtsp://{ip}:{p}/"
                    if not any(s.url == url for s in camera.streams):
                        from .models import StreamInfo as _SI
                        camera.streams.append(_SI(url=url, stream_type="rtsp"))
                    break
            # Try HTTP snapshot candidates on the detected HTTP port ONLY for camera candidates
            if generic_r.get("http_port") and generic_r.get("device_category") == "camera":
                hp = generic_r['http_port']
                from .models import HTTPS_PORTS
                scheme = "https" if hp in HTTPS_PORTS or "443" in str(hp) else "http"
                base_g = f"{scheme}://{ip}:{hp}"
                candidates = []
                if generic_r.get("snapshot_path"):
                    candidates.append(f"{base_g}{generic_r['snapshot_path']}")
                candidates.extend([
                    f"{base_g}/jpg/image.jpg",
                    f"{base_g}/cgi-bin/snapshot.cgi?channel=1",
                    f"{base_g}/snapshot.jpg",
                    f"{base_g}/image.jpg",
                ])
                for c_url in candidates:
                    if not any(s.url == c_url for s in camera.streams):
                        camera.streams.append(StreamInfo(url=c_url, stream_type="http_snapshot"))
                if generic_r.get("rtsp_path"):
                    rtsp_url = f"rtsp://{ip}:{hp}{generic_r['rtsp_path']}"
                    if not any(s.url == rtsp_url for s in camera.streams):
                        from .models import StreamInfo as _SI
                        camera.streams.append(_SI(url=rtsp_url, stream_type="rtsp"))
            if generic_r.get("credentials"):
                camera.credentials = generic_r["credentials"]
            if generic_r.get("auth_required") is not None and camera.auth_required is None:
                camera.auth_required = generic_r["auth_required"]
        else:
            if not camera.brand or camera.brand in ("Generic RTSP", "Generic Web Device", "ONVIF"):
                if generic_r.get("brand"):
                    camera.brand = generic_r["brand"]
            if not camera.model and generic_r.get("model"):
                camera.model = generic_r["model"]
            if not camera.web_title:
                camera.web_title = generic_r.get("title", "")
            if not camera.web_url:
                camera.web_url = generic_r.get("web_url", "")
            if generic_r.get("credentials") and not camera.credentials:
                camera.credentials = generic_r["credentials"]
            if generic_r.get("http_port") and generic_r.get("snapshot_path"):
                hp = generic_r['http_port']
                from .models import HTTPS_PORTS
                scheme = "https" if hp in HTTPS_PORTS or "443" in str(hp) else "http"
                snap_u = f"{scheme}://{ip}:{hp}{generic_r['snapshot_path']}"
                if not any(s.url == snap_u for s in camera.streams):
                    camera.streams.append(StreamInfo(url=snap_u, stream_type="http_snapshot"))
            if generic_r.get("http_port") and generic_r.get("rtsp_path"):
                hp = generic_r['http_port']
                rtsp_u = f"rtsp://{ip}:{hp}{generic_r['rtsp_path']}"
                if not any(s.url == rtsp_u for s in camera.streams):
                    from .models import StreamInfo as _SI
            if generic_r.get("device_category") and camera.device_category == "camera" and not camera.streams and not _is_camera_brand(camera.brand):
                camera.device_category = generic_r.get("device_category")

    if _is_camera_brand(camera.brand):
        camera.device_category = "camera"

    if camera.device_category in ("router", "generic_web", "device") and not _is_camera_brand(camera.brand):
        # For non-camera devices, filter out any generic video/snapshot assumptions
        camera.streams = [
            s for s in camera.streams
            if s.stream_type != "http_snapshot" and "snapshot.cgi" not in s.url and "snapshot.jpg" not in s.url
        ]
        if not camera.streams and (camera.web_url or camera.http_port or open_ports):
            web_port = camera.http_port or (open_ports[0] if open_ports else 80)
            from .models import HTTPS_PORTS
            scheme = "https" if web_port in HTTPS_PORTS or "443" in str(web_port) else "http"
            web_url = camera.web_url or f"{scheme}://{camera.ip}:{web_port}/"
            camera.web_url = web_url
            from .models import StreamInfo as _SI
            camera.streams.append(_SI(
                url=web_url,
                stream_type="web_panel",
                verified=bool(camera.web_screenshot),
                screenshot_path=camera.web_screenshot,
            ))

    if any(r.get("auth_required") for r in (onvif_r, hik_r, dahua_r, axis_r, rtsp_r)):
        camera.auth_required = True

    if not detected:
        # Check if dedicated CCTV ports are open (e.g. 554 RTSP, 34567 Sofia, 37777 Dahua)
        rtsp_cands = [p for p in open_ports if p in RTSP_PORTS or p in {554, 555, 5555, 8554}]
        if rtsp_cands:
            p = rtsp_cands[0]
            camera.brand = "Generic RTSP"
            camera.rtsp_port = p
            camera.auth_required = None
            camera.protocols.append("rtsp_direct")
            from .models import StreamInfo as _SI
            camera.streams.append(_SI(url=f"rtsp://{ip}:{p}/live/ch0", stream_type="rtsp", auth_required=None))
            camera.streams.append(_SI(url=f"rtsp://{ip}:{p}/Streaming/Channels/101", stream_type="rtsp", auth_required=None))
            camera.streams.append(_SI(url=f"rtsp://{ip}:{p}/cam/realmonitor?channel=1&subtype=0", stream_type="rtsp", auth_required=None))
            detected = True
        elif 34567 in open_ports or 34599 in open_ports:
            camera.brand = "Xiongmai"
            camera.model = "NETSurveillance Device"
            camera.auth_required = None
            camera.protocols.append("xiongmai_sofia")
            from .models import StreamInfo as _SI
            camera.streams.append(_SI(url=f"rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0", stream_type="rtsp", auth_required=None))
            detected = True
        elif 37777 in open_ports:
            camera.brand = "Dahua"
            camera.model = "Dahua DVR/NVR"
            camera.auth_required = None
            camera.protocols.append("dahua_dhip")
            from .models import StreamInfo as _SI
            camera.streams.append(_SI(url=f"rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0", stream_type="rtsp", auth_required=None))
            detected = True
        elif 8291 in open_ports:
            # MikroTik Winbox dedicated port
            camera.brand = "MikroTik"
            camera.model = "RouterOS"
            camera.device_category = "router"
            camera.protocols.append("winbox")
            detected = True

    if not detected:
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

    for stream in camera.streams:
        for result in res_map.values():
            if not isinstance(result, dict):
                continue
            urls = set()
            for key, value in result.items():
                if key.endswith("_url") and isinstance(value, str):
                    urls.add(value)
                elif key.endswith("_urls") and isinstance(value, list):
                    urls.update(u for u in value if isinstance(u, str))
                elif key == "streams" and isinstance(value, list):
                    urls.update(u.get("url", "") for u in value if isinstance(u, dict))
            if stream.url in urls:
                stream.credentials = dict(result.get("credentials") or {})
                stream.auth_required = result.get("auth_required")
                stream.source_port = (result.get("onvif_port") or result.get("http_port")
                                      or result.get("open_port") or 0)
                break

    return camera


def universal_observation_to_camera_result(obs) -> Optional[CameraResult]:
    """Convert an EndpointObservation (dict or object) into a CameraResult if video/camera service is detected.

    Supports detection on ANY port, standard or non-standard.
    Returns None if the endpoint is not a video/camera device.
    """
    if hasattr(obs, "to_dict"):
        data = obs.to_dict()
    elif isinstance(obs, dict):
        data = obs
    else:
        return None

    ip = str(data.get("ip", "")).strip()
    if not ip:
        return None

    port = int(data.get("port", 0))
    transport = str(data.get("transport", "tcp")).lower()
    services = data.get("services", [])
    classifications = data.get("classifications", [])

    # Protocol & category matching
    video_protocols = {
        "rtsp", "rtsps", "onvif", "hikvision", "hikvision_isapi",
        "dahua", "dahua_cgi", "dahua_media", "axis", "axis_cgi",
        "hls", "mjpeg", "mpeg-ts", "http_snapshot", "http_media",
        "sofia", "xiongmai", "sprecord", "vms", "webrtc",
    }
    camera_kinds = {"camera", "nvr", "dvr", "vms", "road_camera", "anpr", "audio_recorder", "media_server"}

    is_camera = any(item.get("protocol") in video_protocols for item in data.get("streams", []))
    matched_services = []

    for svc in services:
        proto = str(svc.get("protocol", "")).lower()
        cats = [str(c).lower() for c in svc.get("categories", [])]
        if proto in video_protocols or "video" in cats:
            is_camera = True
            matched_services.append(svc)

    for cls_item in classifications:
        kind = str(cls_item.get("kind", "")).lower()
        if kind in camera_kinds:
            is_camera = True

    # Check dedicated legacy ports if state is open
    if not is_camera and data.get("state") == "open":
        if port in {554, 555, 8554, 10554, 34567, 37777}:
            is_camera = True

    if not is_camera:
        return None

    camera = CameraResult(ip=ip, open_ports=[port] if port else [])
    auth_required = None

    # Inspect classifications for brand/model
    for cls_item in classifications:
        kind = str(cls_item.get("kind", ""))
        evidence = cls_item.get("evidence", [])
        for ev in evidence:
            ev_lower = str(ev).lower()
            if "sprecord" in ev_lower:
                camera.brand = "SpRecord"
                camera.model = "Audio Recorder"
            elif "zoneminder" in ev_lower:
                camera.brand = "ZoneMinder"
                camera.model = "VMS"
            elif "milestone" in ev_lower:
                camera.brand = "Milestone"
                camera.model = "XProtect VMS"
            elif "flussonic" in ev_lower:
                camera.brand = "Flussonic"
                camera.model = "Media Server"
            elif "dahua" in ev_lower:
                camera.brand = "Dahua"
            elif "hikvision" in ev_lower:
                camera.brand = "Hikvision"

    for fingerprint in data.get("fingerprints", []):
        camera.brand = fingerprint.get("vendor") or camera.brand
        camera.model = fingerprint.get("model") or camera.model
        camera.serial = fingerprint.get("serial") or camera.serial
        camera.firmware = fingerprint.get("firmware") or camera.firmware

    # Inspect services
    for svc in matched_services:
        proto = str(svc.get("protocol", "")).lower()
        attr = svc.get("attributes", {})
        auth_required = True if (attr.get("auth_required") is True or attr.get("status_code") == 401) else None
        if attr.get("status_code") in (403, 407):
            auth_required = None
        if auth_required:
            camera.auth_required = True
        stream_start = len(camera.streams)

        server = str(attr.get("server", ""))
        product = str(attr.get("product", ""))
        brand_cand = str(attr.get("brand", "") or attr.get("vendor", ""))
        if brand_cand:
            camera.brand = brand_cand
        elif not camera.brand:
            combined = f"{server} {product}".lower()
            if "hikvision" in combined:
                camera.brand = "Hikvision"
            elif "dahua" in combined:
                camera.brand = "Dahua"
            elif "axis" in combined:
                camera.brand = "Axis"
            elif "sprecord" in combined:
                camera.brand = "SpRecord"
            elif "xiongmai" in combined or "sofia" in combined:
                camera.brand = "Xiongmai"

        # Model and firmware
        if attr.get("model"):
            camera.model = str(attr["model"])
        if attr.get("version"):
            camera.firmware = str(attr["version"])
        if attr.get("serial"):
            camera.serial = str(attr["serial"])

        is_tls = proto == "rtsps" or attr.get("transport_security") or proto == "https"
        scheme = "https" if is_tls else "http"
        path = str(attr.get("path", "/"))

        # Map protocols and build streams
        if proto in ("rtsp", "rtsps"):
            camera.protocols.append("rtsp_direct" if "rtsp_direct" not in camera.protocols else "rtsp")
            camera.rtsp_port = port
            stream_url = attr.get("url") or f"{proto}://{ip}:{port}/"
            camera.streams.append(StreamInfo(url=stream_url, stream_type="rtsp", auth_required=auth_required))

            # Generate candidate RTSP paths matching detected brand or universal wordlists
            brand_lower = (camera.brand or "").lower()
            paths_to_add: List[str] = []
            if "hikvision" in brand_lower or "hilook" in brand_lower:
                paths_to_add = _HIK_PATHS[:10]
            elif "dahua" in brand_lower or "imou" in brand_lower:
                paths_to_add = _DAHUA_PATHS[:8]
            elif "xiongmai" in brand_lower or "xm" in brand_lower:
                paths_to_add = _XM_PATHS[:10]
            elif "axis" in brand_lower:
                paths_to_add = _AXIS_PATHS[:6]
            elif "reolink" in brand_lower:
                paths_to_add = _REOLINK_PATHS
            elif "uniview" in brand_lower or "unv" in brand_lower:
                paths_to_add = _UNV_PATHS
            elif "beward" in brand_lower:
                paths_to_add = _BEWARD_PATHS
            elif "samsung" in brand_lower or "hanwha" in brand_lower:
                paths_to_add = _SAMSUNG_PATHS[:6]
            else:
                brand_db_paths = _get_brand_rtsp_paths(camera.brand)
                if brand_db_paths:
                    paths_to_add = brand_db_paths[:8]
                else:
                    paths_to_add = _GENERIC_PATHS[:15]

            for cand_path in paths_to_add:
                cand_url = f"rtsp://{ip}:{port}{cand_path}"
                camera.streams.append(StreamInfo(url=cand_url, stream_type="rtsp", auth_required=auth_required))

        elif proto == "rtmp":
            camera.protocols.append("rtmp")
            camera.rtmp_port = port
            for rtmp_path in _RTMP_PATHS:
                camera.streams.append(StreamInfo(url=f"rtmp://{ip}:{port}{rtmp_path}", stream_type="rtmp", auth_required=auth_required))
        elif proto == "onvif":
            camera.protocols.append("onvif")
            camera.onvif_port = port
            camera.http_port = camera.http_port or port
            for u in attr.get("rtsp_urls", []):
                camera.streams.append(StreamInfo(url=u, stream_type="rtsp", auth_required=auth_required))
        elif proto in ("hikvision", "hikvision_isapi"):
            camera.protocols.append("hikvision_isapi")
            camera.brand = camera.brand or "Hikvision"
            camera.http_port = port
            if attr.get("snapshot_url"):
                camera.streams.append(StreamInfo(url=attr["snapshot_url"], stream_type="http_snapshot", auth_required=auth_required))
        elif proto in ("dahua", "dahua_cgi", "dahua_media"):
            camera.protocols.append("dahua_cgi")
            camera.brand = camera.brand or "Dahua"
            camera.http_port = port
        elif proto == "hls":
            camera.protocols.append("hls")
            camera.http_port = port
            camera.streams.append(StreamInfo(url=f"{scheme}://{ip}:{port}{path}", stream_type="hls", auth_required=auth_required))
        elif proto == "mjpeg":
            camera.protocols.append("mjpeg")
            camera.http_port = port
            camera.streams.append(StreamInfo(url=f"{scheme}://{ip}:{port}{path}", stream_type="mjpeg", auth_required=auth_required))
        elif proto == "http_snapshot":
            camera.protocols.append("http_snapshot")
            camera.http_port = port
            camera.streams.append(StreamInfo(url=f"{scheme}://{ip}:{port}{path}", stream_type="http_snapshot", auth_required=auth_required))
        elif proto == "sprecord":
            camera.protocols.append("sprecord_audio")
            camera.brand = "SpRecord"
            camera.http_port = port
            camera.streams.append(StreamInfo(url=f"http://{ip}:{port}/audio", stream_type="http_audio", auth_required=auth_required))
        else:
            if proto not in camera.protocols:
                camera.protocols.append(proto)

        for stream in camera.streams[stream_start:]:
            stream.source_port = port
            stream.credentials = dict(attr.get("credentials") or {})

    if not camera.brand:
        if "rtsp_direct" in camera.protocols or "rtsp" in camera.protocols:
            camera.brand = "Generic RTSP"
        elif any(p in camera.protocols for p in ("hls", "mjpeg", "http_snapshot")):
            camera.brand = "Web Stream"
        else:
            camera.brand = "Unknown Camera"

    # Default fallback stream if RTSP port without streams
    if not camera.streams and (camera.rtsp_port or port in {554, 8554}):
        p = camera.rtsp_port or port
        camera.rtsp_port = p
        camera.streams.append(StreamInfo(url=f"rtsp://{ip}:{p}/", stream_type="rtsp", auth_required=auth_required))
        for cand_path in _GENERIC_PATHS[:10]:
            camera.streams.append(StreamInfo(url=f"rtsp://{ip}:{p}{cand_path}", stream_type="rtsp", auth_required=auth_required))


    camera.endpoints = [{"port": port, "transport": transport,
                         "brand": camera.brand, "model": camera.model, "serial": camera.serial,
                         "protocols": list(camera.protocols), "auth_required": camera.auth_required}]

    # Inventory plugins store actual channel URIs separately from service metadata.
    advertised = []
    for item in data.get("streams", []):
        uri = item.get("uri") or item.get("url")
        if not uri:
            continue
        from urllib.parse import urlsplit
        proto = item.get("protocol") or urlsplit(uri).scheme
        if proto not in ("rtsp", "rtsps", "rtmp", "hls", "mjpeg", "http_snapshot"):
            continue
        advertised.append(StreamInfo(url=uri, stream_type=proto, source_port=port,
                                     credentials=dict(item.get("credentials") or {})))
    camera.streams = advertised + camera.streams

    # Dedup protocols and streams
    camera.protocols = list(dict.fromkeys(camera.protocols))
    seen_urls = set()
    dedup_streams = []
    for s in camera.streams:
        if s.url not in seen_urls:
            seen_urls.add(s.url)
            dedup_streams.append(s)
    camera.streams = dedup_streams

    return camera


def project_observation_to_cameras(obs, storage=None) -> Optional[CameraResult]:
    """Project an EndpointObservation into storage.save_v2_result and camera_devices if it's a camera."""
    camera = universal_observation_to_camera_result(obs)
    if camera is None:
        return None

    if storage is None:
        try:
            from ip2domain.web.routers.common import storage as default_storage
            storage = default_storage
        except Exception:
            storage = None

    if storage is not None:
        try:
            if hasattr(storage, "save_v2_result"):
                storage.save_v2_result(camera.to_dict())
            if hasattr(storage, "save_camera_devices"):
                device_entry = {
                    "target": camera.ip,
                    "hostname": "",
                    "score": 90 if camera.streams else 70,
                    "confidence": "high" if len(camera.protocols) > 1 else "medium",
                    "brand": camera.brand,
                    "model": camera.model,
                    "protocols": camera.protocols,
                    "open_ports": camera.open_ports,
                    "streams": [s.to_dict() for s in camera.streams],
                    "auth_required": camera.auth_required,
                }
                storage.save_camera_devices([device_entry])
        except Exception as err:
            import logging
            logging.getLogger(__name__).warning("Error projecting camera to storage: %s", err)

    return camera
