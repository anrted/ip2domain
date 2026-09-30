"""Synthesizes actionable device endpoints and metadata for any identified network device.

Transforms raw EndpointObservation documents into structured device profiles
with directly clickable Web UI, live stream, snapshot, telemetry and API endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from ..classification_catalog import CATEGORY_META, DeviceRule, match_device_rule


def synthesize_device_endpoints(observation) -> Dict[str, Any]:
    """Inspect services, banners, and classifications to produce an actionable device profile."""
    services = getattr(observation, "services", [])
    ip = getattr(observation, "ip", "")
    port = getattr(observation, "port", 0)

    # Collect all available text evidence
    text_corpus: List[str] = []
    auth_required = False
    open_ports = [port] if port else []

    # Check services
    http_svc = None
    rtsp_svc = None
    rtmp_svc = None

    for svc in services:
        proto = svc.get("protocol", "").lower()
        attrs = svc.get("attributes", {})
        if proto in ("http", "https"):
            http_svc = svc
        elif proto in ("rtsp", "rtsps"):
            rtsp_svc = svc
        elif proto == "rtmp":
            rtmp_svc = svc

        if attrs.get("auth_required") or attrs.get("status_code") in (401, 403, 407):
            auth_required = True

        if proto:
            text_corpus.append(str(proto))
        for field_name in ("server", "product", "banner", "model", "vendor", "brand", "auth_scheme", "title", "generator", "body_clues", "realm"):
            val = str(attrs.get(field_name, "")).strip()
            if val:
                text_corpus.append(val)

    combined_text = " ".join(text_corpus)

    # Match device rule from classification catalog
    rule = match_device_rule(combined_text, tuple(open_ports))

    # Base URLs
    is_tls = any(s.get("protocol") == "https" or s.get("attributes", {}).get("transport_security") for s in services)
    http_scheme = "https" if is_tls else "http"

    # Default URLs
    web_url = f"{http_scheme}://{ip}:{port}/" if (http_svc or port in (80, 443, 8080, 8443, 8000, 8088)) else ""
    snapshot_url = ""
    stream_url = ""
    telemetry_url = ""
    api_url = ""

    category = "general"
    category_label = "Сетевой сервис"
    category_icon = "⚙️"
    device_type = "network_device"
    type_label = "Сетевое устройство"
    vendor = "Generic"
    model = ""

    if rule:
        category = rule.category
        meta = CATEGORY_META.get(category, {})
        category_label = meta.get("label", category.title())
        category_icon = meta.get("icon", "⚙️")
        device_type = rule.device_type
        type_label = rule.type_label
        vendor = rule.vendor
        model = rule.model

        # Build specific URLs
        if rule.web_path:
            clean_path = rule.web_path if rule.web_path.startswith("/") else "/" + rule.web_path
            web_url = f"{http_scheme}://{ip}:{port}{clean_path}"

        if rule.snapshot_path:
            clean_snap = rule.snapshot_path if rule.snapshot_path.startswith("/") else "/" + rule.snapshot_path
            snapshot_url = f"{http_scheme}://{ip}:{port}{clean_snap}"

        if rule.stream_path:
            clean_stream = rule.stream_path if rule.stream_path.startswith("/") else "/" + rule.stream_path
            if rule.stream_path.startswith("rtsp://") or rule.stream_path.startswith("http"):
                stream_url = rule.stream_path
            elif clean_stream.startswith(("/Streaming", "/cam/", "/axis-media", "/unicast", "/live", "/h264", "/onvif")):
                rtsp_p = port if rtsp_svc else 554
                stream_url = f"rtsp://{ip}:{rtsp_p}{clean_stream}"
            else:
                stream_url = f"rtsp://{ip}:{port}{clean_stream}" if rtsp_svc else f"{http_scheme}://{ip}:{port}{clean_stream}"

        if rule.telemetry_path:
            clean_telem = rule.telemetry_path if rule.telemetry_path.startswith("/") else "/" + rule.telemetry_path
            telemetry_url = f"{http_scheme}://{ip}:{port}{clean_telem}"

        if rule.api_path:
            if "://" in rule.api_path:
                api_url = f"{rule.api_path}{ip}:{port}"
            else:
                clean_api = rule.api_path if rule.api_path.startswith("/") else "/" + rule.api_path
                api_url = f"{http_scheme}://{ip}:{port}{clean_api}"

    # Streams collection
    streams: List[Dict[str, Any]] = []
    rtsp_port = port if (rtsp_svc and rtsp_svc.get("port") is None) else (rtsp_svc.get("port", 554) if rtsp_svc else 554)

    # ── Use verified RTSP probe results when available ────────────────────
    # enrich_rtsp() stores probe results under _rtsp_* keys in device_info.
    # These are real network-verified streams with working credentials already
    # embedded in the URL (e.g. rtsp://admin:12345@ip:554/Streaming/Channels/101).
    existing_di = getattr(observation, "device_info", {}) or {}
    rtsp_probed = existing_di.get("_rtsp_probed", False)

    if rtsp_probed:
        probed_streams = existing_di.get("_rtsp_streams", [])
        probed_brand = existing_di.get("_rtsp_brand", "")
        probed_creds = existing_di.get("_rtsp_credentials", {})
        probed_auth_req = existing_di.get("_rtsp_auth_required", False)

        if probed_brand and vendor == "Generic":
            vendor = probed_brand
        if probed_auth_req:
            auth_required = True

        for ps in probed_streams:
            if not any(s["url"] == ps["url"] for s in streams):
                streams.append(ps)

        if probed_streams and not stream_url:
            stream_url = probed_streams[0]["url"]
            if category == "general":
                category = "video"
                meta = CATEGORY_META.get("video", {})
                category_label = meta.get("label", "Видеонаблюдение")
                category_icon = meta.get("icon", "📹")
                device_type = "camera"
                type_label = "RTSP Видеопоток"

    # ── Fallback: static stream presets (when no RTSP probe was done) ─────
    # Fallbacks from discovered services
    is_hik = (
        vendor in ("Hikvision", "HiWatch")
        or "hikvision" in combined_text
        or "hiwatch" in combined_text
        or 8000 in open_ports
        or "doc/page/login.asp" in combined_text
    )
    is_dahua = vendor == "Dahua" or "dahua" in combined_text or 37777 in open_ports
    is_axis = vendor == "Axis" or "axis" in combined_text

    if not rtsp_probed:
        if is_hik and not stream_url:
            stream_url = f"rtsp://{ip}:{rtsp_port}/Streaming/Channels/101"
        elif is_dahua and not stream_url:
            stream_url = f"rtsp://{ip}:{rtsp_port}/cam/realmonitor?channel=1&subtype=0"
        elif is_axis and not stream_url:
            stream_url = f"rtsp://{ip}:{rtsp_port}/axis-media/media.amp"
        elif rtsp_svc and not stream_url:
            # Default to standard RTSP channel 1
            stream_url = f"rtsp://{ip}:{rtsp_port}/Streaming/Channels/101"
            if category == "general":
                category = "video"
                meta = CATEGORY_META.get("video", {})
                category_label = meta.get("label", "Видеонаблюдение")
                category_icon = meta.get("icon", "📹")
                device_type = "camera"
                type_label = "RTSP Видеопоток"

    if rtmp_svc and not stream_url:
        stream_url = f"rtmp://{ip}:{port}/live"
        if category == "general":
            category = "video"
            category_icon = "📹"
            category_label = "Видеостриминг (RTMP)"

    if stream_url and not any(s["url"] == stream_url for s in streams):
        st_type = "rtmp" if stream_url.startswith("rtmp") else ("http" if stream_url.startswith("http") else "rtsp")
        streams.insert(0, {
            "url": stream_url,
            "type": st_type,
            "stream_type": st_type,
            "title": "Основной поток (Main Ch1)",
            "verified": rtsp_probed,
        })

    # Brand presets and common channels (only add unverified static hints when no probe was done)
    if not rtsp_probed:
        if is_hik:
            hik_channels = [
                ("/Streaming/Channels/101", "Канал 1 · Основной поток (1080p/4K)"),
                ("/Streaming/Channels/102", "Канал 1 · Суб-поток (Substream)"),
                ("/Streaming/Channels/201", "Канал 2 · Основной поток"),
                ("/Streaming/Channels/202", "Канал 2 · Суб-поток"),
                ("/Streaming/Channels/301", "Канал 3 · Основной поток"),
                ("/Streaming/Channels/401", "Канал 4 · Основной поток"),
                ("/h264/ch1/main/av_stream", "H.264 Ch1 Main AV Stream"),
            ]
            for cpath, ctitle in hik_channels:
                curl = f"rtsp://{ip}:{rtsp_port}{cpath}"
                if not any(s["url"] == curl for s in streams):
                    streams.append({
                        "url": curl,
                        "type": "rtsp",
                        "stream_type": "rtsp",
                        "title": ctitle,
                        "verified": False,
                    })
        elif is_dahua:
            dahua_channels = [
                ("/cam/realmonitor?channel=1&subtype=0", "Канал 1 · Основной поток (Main)"),
                ("/cam/realmonitor?channel=1&subtype=1", "Канал 1 · Суб-поток (Substream)"),
                ("/cam/realmonitor?channel=2&subtype=0", "Канал 2 · Основной поток"),
                ("/cam/realmonitor?channel=2&subtype=1", "Канал 2 · Суб-поток"),
                ("/live", "Live RTSP"),
            ]
            for cpath, ctitle in dahua_channels:
                curl = f"rtsp://{ip}:{rtsp_port}{cpath}"
                if not any(s["url"] == curl for s in streams):
                    streams.append({
                        "url": curl,
                        "type": "rtsp",
                        "stream_type": "rtsp",
                        "title": ctitle,
                        "verified": False,
                    })
        elif category == "video" or rtsp_svc:
            generic_channels = [
                ("/Streaming/Channels/101", "Hikvision / HiWatch Канал 1"),
                ("/Streaming/Channels/102", "Hikvision / HiWatch Суб-поток"),
                ("/cam/realmonitor?channel=1&subtype=0", "Dahua Канал 1"),
                ("/cam/realmonitor?channel=1&subtype=1", "Dahua Суб-поток"),
                ("/onvif1", "ONVIF Profile 1"),
                ("/live/ch0", "Generic RTSP (Xiongmai / Jovision)"),
                ("/0", "Канал 0"),
                ("/1", "Канал 1"),
                ("/h264", "H.264 Stream"),
            ]
            for cpath, ctitle in generic_channels:
                curl = f"rtsp://{ip}:{rtsp_port}{cpath}"
                if not any(s["url"] == curl for s in streams):
                    streams.append({
                        "url": curl,
                        "type": "rtsp",
                        "stream_type": "rtsp",
                        "title": ctitle,
                        "verified": False,
                    })

    if snapshot_url:
        streams.append({
            "url": snapshot_url,
            "type": "http_snapshot",
            "stream_type": "http_snapshot",
            "title": "Снимок (Live Snapshot)",
            "verified": True,
        })

    if not stream_url and streams:
        stream_url = streams[0]["url"]

    # Actionable interaction buttons for the UI
    actions: List[Dict[str, str]] = []

    if web_url:
        actions.append({"id": "web", "label": "Web UI", "icon": "🌐", "url": web_url})

    if snapshot_url:
        actions.append({"id": "snapshot", "label": "Снимок", "icon": "📸", "url": snapshot_url})

    if stream_url or streams:
        actions.append({"id": "stream", "label": "Стрим", "icon": "🎥", "url": stream_url or streams[0]["url"]})

    if telemetry_url:
        actions.append({"id": "telemetry", "label": "Телеметрия", "icon": "📊", "url": telemetry_url})

    if api_url:
        actions.append({"id": "api", "label": "API / Порт", "icon": "🔌", "url": api_url})

    return {
        "category": category,
        "category_label": category_label,
        "category_icon": category_icon,
        "type": device_type,
        "type_label": type_label,
        "vendor": vendor,
        "model": model,
        "web_url": web_url,
        "snapshot_url": snapshot_url,
        "stream_url": stream_url,
        "streams": streams,
        "telemetry_url": telemetry_url,
        "api_url": api_url,
        "auth_required": auth_required,
        "actions": actions,
    }
