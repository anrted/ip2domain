"""Direct RTSP DESCRIBE probe for Camera Scanner v2.

Sends raw RTSP OPTIONS + DESCRIBE over TCP to detect live streams
and identify camera vendor from RTSP Server header.
Includes exhaustive path wordlist for all major camera manufacturers.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

# ─────────────────────────────────────────────────────────────────────────────
# Vendor-specific and generic RTSP stream path catalogs
# ─────────────────────────────────────────────────────────────────────────────

# Xiongmai / XM / NetIP / H.264 DVR
_XM_PATHS = [
     "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif",
     "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
     "/cam/realmonitor?channel=2&subtype=0&unicast=true&proto=Onvif",
     "/cam/realmonitor?channel=1&subtype=0",
     "/cam/realmonitor?channel=1&subtype=1",
     "/cam/realmonitor?channel=0&subtype=1",
     "/cam/realmonitor",
     "/0",
     "/1",
     "/11",
     "/ch0_0.h264",
     "/h264_pcm.sdp",
     "/user=admin_password=_channel=1_stream=0.sdp",
     "/user=admin_password=_channel=1_stream=1.sdp",
     "/user=admin_password=_channel=0_stream=0.sdp",
     "/user=admin_password=_channel=2_stream=0.sdp",
     "/h264.sdp",
     "/h264",
     "/cam0/h264",
     "/cam1/h264",
     "/cam/h264",
     "/cam0/mjpeg",
     "/cam1/mjpeg",
     "/cam1/mpeg4",
     "/h264_stream",
     "/live/ch00_0",
     "/live/ch0",
     "/onvif1",
     "/live.sdp",
     "/ucast/11",
     "/mpeg4",
     "/",
]

# Hikvision / Ezviz / HiLook
_HIK_PATHS = [
    # Multi-channel standard
    "/Streaming/Channels/1",
    "/Streaming/Channels/101",
    "/Streaming/channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/001",
    "/Streaming/Channels/2",
    "/Streaming/channels/201",
    "/Streaming/channels/202",
    "/Streaming/Channels/201",
    "/Streaming/Channels/301",
    "/Streaming/channels/301",
    "/Streaming/channels/401",
    "/Streaming/Channels/401",
    "/Streaming/channels/501",
    "/Streaming/channels/601",
    "/Streaming/channels/701",
    "/Streaming/channels/702",
    "/Streaming/channels/801",
    "/Streaming/channels/901",
    "/Streaming/channels/1001",
    "/Streaming/channels/1101",
    "/Streaming/channels/1201",
    "/Streaming/channels/1301",
    "/Streaming/channels/1401",
    "/Streaming/channels/1501",
    "/Streaming/channels/1601",
    # Unicast channels
    "/Streaming/Unicast/channels/101",
    "/Streaming/Unicast/channels/201",
    "/Streaming/Unicast/channels/301",
    "/Streaming/Unicast/channels/401",
    "/Streaming/Unicast/channels/501",
    "/Streaming/Unicast/channels/601",
    # Direct RTSP H.264 streams
    "/H264/ch1/main/av_stream",
    "/H264/ch1/sub/av_stream",
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/h264/ch01/main/av_stream",
    "/h264/ch01/sub/av_stream",
    # ISAPI & PSIA
    "/ISAPI/Streaming/channels/101",
    "/ISAPI/Streaming/channels/102",
    "/PSIA/streaming/channels/101",
    "/PSIA/streaming/channels/102",
    "/PSIA/streaming/channels/1",
    "/PSIA/Streaming/channels/1?videoCodecType=MPEG4",
]

# Dahua / Imou / Lorex / Lechange / IC Realtime
_DAHUA_PATHS = [
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif",
    "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
    "/cam/realmonitor?channel=2&subtype=0",
    "/cam/realmonitor?channel=2&subtype=1",
    "/cam/realmonitor?channel=2&subtype=0&unicast=true&proto=Onvif",
    "/cam/realmonitor?channel=2&subtype=1&unicast=true&proto=Onvif",
    "/cam/realmonitor?channel=0&subtype=0",
    "/live",
]

# Axis
_AXIS_PATHS = [
    "/axis-media/media.amp",
    "/axis-media/media.amp?videocodec=h264",
    "/axis-media/media.amp?videocodec=h265",
    "/axis-media/media.amp?camera=1",
    "/axis-media/media.amp?camera=2",
    "/axis-media/media.3gp",
    "/onvif-media/media.amp",
    "/mpeg4/media.amp",
    "/mpeg4/1/media.amp",
    "/mjpg/media.amp",
]

# Uniview / UNV
_UNV_PATHS = [
    "/unicast/c1/s0/live",
    "/unicast/c1/s1/live",
    "/media/video1",
    "/media/video2",
    "/video1",
    "/video2",
]

# Reolink
_REOLINK_PATHS = [
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/preview_01_main",
    "/preview_01_sub",
]

# Beward / Av0 (Russian intercoms & IP cameras)
_BEWARD_PATHS = [
    "/av0_0",
    "/av0_1",
    "/tcp/av0_0",
    "/tcp/av0_1",
]

# Topsvision / Topsee / Jovision
_TOPSVISION_PATHS = [
    "/profile1",
    "/profile2",
    "/profile3",
    "/live0.264",
    "/live1.264",
    "/ch01.264",
    "/ch01_sub.264",
    "/stream1",
    "/stream2",
    "/live/ch0",
    "/live/ch1",
]

# Digital Watchdog
_DW_PATHS = [
    "/rtsp/unicast/live/profile-1",
    "/rtsp/unicast/live/profile-2",
    "/rtsp/unicast/live/profile-3",
    "/rtsp/unicast/live/profile-4",
]

# D-Link
_DLINK_PATHS = [
    "/live1.sdp",
    "/live2.sdp",
    "/live3.sdp",
    "/play1.sdp",
    "/play2.sdp",
    "/play3.sdp",
]

# Panasonic
_PANASONIC_PATHS = [
    "/MediaInput/h264",
    "/nphMpeg4/nil-640x480",
]

# Samsung / Hanwha / Wisenet
_SAMSUNG_PATHS = [
    "/0/profile2/media.smp",
    "/1/profile2/media.smp",
    "/0/profile1/media.smp",
    "/profile1/media.smp",
    "/profile2/media.smp",
    "/onvif/profile1/media.smp",
]

# 2N Helios / IP Intercoms
_2N_PATHS = [
    "/h264_stream",
    "/mjpeg_stream",
    "/mpeg4_stream",
    "/",
]

# Grandstream GDS3710 / GDS3712 / IP Cameras
_GRANDSTREAM_PATHS = [
    "/0",
    "/4",
    "/8",
    "/1",
    "/channel1",
]

# Milesight
_MILESIGHT_PATHS = [
    "/main",
    "/sub",
]

# Tiandy / Grandstream / Foscam / Generic / Other DVR
_GENERIC_PATHS = [
    "/av0_0",
    "/av0_1",
    "/live/ch0",
    "/axis-media/media.amp",
    "/profile1",
    "/profile2",
    "/profile3",
    "/cam0/h264",
    "/cam1/h264",
    "/live.sdp",
    "/h264",
    "/h264.sdp",
    "/h265",
    "/h265.sdp",
    "/live/ch1",
    "/live/main",
    "/live/sub",
    "/live0.264",
    "/live1.264",
    "/ch01.264",
    "/ch01_sub.264",
    "/ch0_0.h264",
    "/ch0_1.h264",
    "/ch1_0.h264",
    "/ch0",
    "/ch1",
    "/0",
    "/1",
    "/0/video.sdp",
    "/1/video.sdp",
    "/1/h264major",
    "/1/h264minor",
    "/11",
    "/12",
    "/21",
    "/22",
    "/1/1",
    "/1/2",
    "/videoMain",
    "/videoSub",
    "/video1",
    "/video2",
    "/onvif1",
    "/onvif2",
    "/MediaInput/h264",
    "/nphMpeg4/nil-640x480",
    "/play1.sdp",
    "/play2.sdp",
    "/live1.sdp",
    "/live2.sdp",
    "/stream1",
    "/stream2",
    "/snx/live/ch0",
    "/PSIA/streaming/channels/101",
    "/rtsp/unicast/live/profile-1",
    "/profile1/media.smp",
    "/",
]

_RTSP_BRAND_PATTERNS = [
    (r"beward", "Beward"),
    (r"2n|helios|verso", "2N"),
    (r"grandstream|gds", "Grandstream"),
    (r"rubetek", "Rubetek"),
    (r"milesight", "Milesight"),
    (r"topsvision|topsee", "Topsvision"),
    (r"jovision", "Jovision"),
    (r"h264dvr|xiongmai|xm|netip", "Xiongmai"),
    (r"hikvision|hik|ds-|ezviz|hilook", "Hikvision"),
    (r"dahua|dh-|imou|lorex|ic realtime", "Dahua"),
    (r"axis", "Axis"),
    (r"uniview|unv", "Uniview"),
    (r"foscam", "Foscam"),
    (r"reolink", "Reolink"),
    (r"amcrest", "Amcrest"),
    (r"grandstream", "Grandstream"),
    (r"tplink|tp-link|tapo", "TP-Link"),
    (r"mobotix", "Mobotix"),
    (r"vivotek", "Vivotek"),
    (r"tiandy", "Tiandy"),
    (r"geovision", "GeoVision"),
    (r"milesight", "Milesight"),
    (r"tvt", "TVT"),
    (r"sunell", "Sunell"),
    (r"wisenet|hanwha|samsung", "Hanwha"),
    (r"sony", "Sony"),
    (r"bosch", "Bosch"),
    (r"panasonic", "Panasonic"),
    (r"d-link|dlink", "D-Link"),
    (r"digital watchdog|vmax", "Digital Watchdog"),
    (r"sharx", "Sharx"),
    (r"embedded net dvr", "Hikvision"),
    (r"ipcam|ip camera|netcam", "Generic IPCam"),
    (r"nvr|dvr|streamer", "Generic DVR"),
]


async def _rtsp_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    method: str,
    url: str,
    cseq: int,
    extra: str = "",
    timeout: float = 1.5,
) -> str:
    """Send a single RTSP request and return the response."""
    req = (
        f"{method} {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"{extra}"
        "\r\n"
    )
    try:
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        return data.decode(errors="ignore")
    except Exception:
        return ""


def _detect_brand_from_rtsp_text(text: str) -> str:
    lower = text.lower()
    for pat, brand in _RTSP_BRAND_PATTERNS:
        if re.search(pat, lower):
            return brand
    return ""


import json
from pathlib import Path

_COMPILED_DB_PATH = Path(__file__).resolve().parent.parent / "cam_db_compiled.json"
_COMPILED_DB = None


def _get_compiled_db() -> dict:
    global _COMPILED_DB
    if _COMPILED_DB is None:
        if _COMPILED_DB_PATH.exists():
            try:
                with open(_COMPILED_DB_PATH, "r", encoding="utf-8") as f:
                    _COMPILED_DB = json.load(f)
            except Exception:
                _COMPILED_DB = {}
        else:
            _COMPILED_DB = {}
    return _COMPILED_DB or {}


def _get_brand_rtsp_paths(brand: str) -> List[str]:
    """Retrieve brand-specific RTSP paths from compiled StrixCamDB (1000+ brands)."""
    db = _get_compiled_db()
    if not db:
        return []
    b_norm = (brand or "").lower().strip()
    brand_map = db.get("brand_rtsp", {})
    if b_norm in brand_map:
        return brand_map[b_norm]
    for k, paths in brand_map.items():
        if len(k) >= 3 and (k in b_norm or b_norm in k):
            return paths
    return []


def _format_rtsp_url(ip: str, port: int, path: str, user: str = "", password: str = "") -> str:
    if user:
        return f"rtsp://{user}:{password}@{ip}:{port}{path}"
    return f"rtsp://{ip}:{port}{path}"


def _build_digest_header(user: str, cred_val: str, method: str, url: str, www_auth: str) -> str:
    """Build RFC 2617 RTSP Digest Authorization header from 401 WWW-Authenticate challenge."""
    realm_m = re.search(r'realm=["\']?([^"\',\r\n]+)["\']?', www_auth, re.IGNORECASE)
    nonce_m = re.search(r'nonce=["\']?([^"\',\r\n]+)["\']?', www_auth, re.IGNORECASE)
    if not realm_m or not nonce_m:
        return ""
    realm = realm_m.group(1).strip()
    nonce = nonce_m.group(1).strip()
    def md5(s: str) -> str:
        return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()
    ha1 = md5(f"{user}:{realm}:{cred_val}")
    ha2 = md5(f"{method}:{url}")
    resp = md5(f"{ha1}:{nonce}:{ha2}")
    return f'Authorization: Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{url}", response="{resp}"\r\n'


async def probe_rtsp_direct(
    ip: str,
    rtsp_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Send RTSP OPTIONS + DESCRIBE to detect live streams.

    Returns: success, rtsp_urls, sdp_info, open_port, brand, credentials
    """
    result = {
        "success": False,
        "rtsp_urls": [],
        "sdp_info": "",
        "open_port": 0,
        "brand": "",
        "credentials": {},
    }

    ports_to_try = rtsp_ports or [554]

    for port in ports_to_try:
        reader = None
        writer = None

        async def ensure_conn():
            nonlocal reader, writer
            if writer and not writer.is_closing():
                return reader, writer
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=_TIMEOUT
                )
                return reader, writer
            except Exception:
                return None, None

        r, w = await ensure_conn()
        if not r or not w:
            continue

        try:
            base_url = f"rtsp://{ip}:{port}"

            # 1. OPTIONS — confirm it's RTSP and extract vendor
            opts = await _rtsp_request(reader, writer, "OPTIONS", base_url + "/", 1, timeout=2.0)
            is_rtsp = ("RTSP/1.0" in opts or "Public:" in opts or "Server:" in opts)
            
            # Some RTSP servers (e.g. Hikvision DVRs) return 404 on OPTIONS / but are fully functional RTSP servers
            if not is_rtsp:
                check_desc = await _rtsp_request(reader, writer, "DESCRIBE", base_url + "/Streaming/Channels/101", 1, timeout=2.0)
                if "RTSP/1.0" in check_desc or "WWW-Authenticate" in check_desc or "401" in check_desc or "200 OK" in check_desc:
                    is_rtsp = True
                    opts = check_desc

            if not is_rtsp:
                continue

            result["open_port"] = port

            brand = _detect_brand_from_rtsp_text(opts)
            if not brand:
                check_desc = await _rtsp_request(reader, writer, "DESCRIBE", base_url + "/Streaming/Channels/101", 2, timeout=1.5)
                brand = _detect_brand_from_rtsp_text(check_desc)
                if not brand:
                    check_desc2 = await _rtsp_request(reader, writer, "DESCRIBE", base_url + "/h264_pcm.sdp", 3, timeout=1.5)
                    brand = _detect_brand_from_rtsp_text(check_desc2)
            if brand:
                result["brand"] = brand

            # Query compiled StrixCamDB for brand-specific paths
            db_brand_paths = _get_brand_rtsp_paths(result["brand"]) if result["brand"] else []

            # Select primary candidate paths based on vendor
            if result["brand"] == "Beward":
                probe_paths = _BEWARD_PATHS + [p for p in db_brand_paths if p not in _BEWARD_PATHS]
            elif result["brand"] == "2N":
                probe_paths = _2N_PATHS + [p for p in db_brand_paths if p not in _2N_PATHS]
            elif result["brand"] == "Grandstream":
                probe_paths = _GRANDSTREAM_PATHS + [p for p in db_brand_paths if p not in _GRANDSTREAM_PATHS]
            elif result["brand"] == "Milesight":
                probe_paths = _MILESIGHT_PATHS + [p for p in db_brand_paths if p not in _MILESIGHT_PATHS]
            elif result["brand"] == "Rubetek":
                probe_paths = ["/av0_0", "/av0_1", "/live/ch0", "/live/main", "/profile1"] + [p for p in db_brand_paths if p not in _BEWARD_PATHS]
            elif result["brand"] == "Topsvision":
                probe_paths = _TOPSVISION_PATHS + [p for p in db_brand_paths if p not in _TOPSVISION_PATHS]
            elif result["brand"] == "Jovision":
                probe_paths = ["/0", "/1", "/ch0", "/ch1", "/profile1", "/profile2"] + db_brand_paths
            elif result["brand"] == "Xiongmai":
                probe_paths = _XM_PATHS + [p for p in db_brand_paths if p not in _XM_PATHS]
            elif result["brand"] == "Hikvision":
                probe_paths = _HIK_PATHS + [p for p in db_brand_paths if p not in _HIK_PATHS]
            elif result["brand"] == "Dahua":
                probe_paths = _DAHUA_PATHS + [p for p in db_brand_paths if p not in _DAHUA_PATHS]
            elif result["brand"] == "Axis":
                probe_paths = _AXIS_PATHS + [p for p in db_brand_paths if p not in _AXIS_PATHS]
            elif result["brand"] == "Uniview":
                probe_paths = _UNV_PATHS + [p for p in db_brand_paths if p not in _UNV_PATHS]
            elif result["brand"] == "Reolink":
                probe_paths = _REOLINK_PATHS + [p for p in db_brand_paths if p not in _REOLINK_PATHS]
            elif result["brand"] == "Digital Watchdog":
                probe_paths = _DW_PATHS + [p for p in db_brand_paths if p not in _DW_PATHS]
            elif result["brand"] == "D-Link":
                probe_paths = _DLINK_PATHS + [p for p in db_brand_paths if p not in _DLINK_PATHS]
            elif result["brand"] == "Panasonic":
                probe_paths = _PANASONIC_PATHS + [p for p in db_brand_paths if p not in _PANASONIC_PATHS]
            elif result["brand"] == "Hanwha":
                probe_paths = _SAMSUNG_PATHS + [p for p in db_brand_paths if p not in _SAMSUNG_PATHS]
            elif db_brand_paths:
                probe_paths = db_brand_paths[:60]
            else:
                top_db = _get_compiled_db().get("top_rtsp", [])
                base_probe = (top_db[:60] if top_db else []) or _GENERIC_PATHS[:60]
                priority_paths = [
                    "/av0_0",
                    "/av0_1",
                    "/0",
                    "/1",
                    "/cam0/h264",
                    "/ch0_0.h264",
                    "/live/ch0",
                    "/axis-media/media.amp",
                    "/Streaming/Channels/101",
                    "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif",
                    "/cam/realmonitor?channel=1&subtype=0",
                    "/h264_pcm.sdp",
                    "/user=admin_password=_channel=1_stream=0.sdp",
                    "/h264.sdp",
                ]
                probe_paths = priority_paths + [p for p in base_probe if p not in priority_paths]

            # Filter out non-RTSP web assets mistakenly compiled into brand databases (e.g. /doc/index.html)
            probe_paths = [
                p for p in probe_paths
                if not re.search(r"\.(html?|png|jpe?g|gif|css|js|asp|txt|xml|ico)($|\?)", p, re.IGNORECASE)
            ]

            found_urls: List[str] = []
            failed_auth_paths = 0
            cseq = 4
            cached_working_cred: Optional[Tuple[str, str]] = None
            cached_auth_hdr_challenge: str = opts if ("401" in opts or "WWW-Authenticate" in opts) else ""
            auth_exhausted: bool = False

            # If working credentials were already discovered or provided, prioritize them
            default_creds = [("admin", ""), ("admin", "admin"), ("admin", "12345"), ("admin", "123456"), ("root", "root"), ("root", "")]
            active_creds = credentials if credentials else default_creds

            for path in probe_paths:
                url = base_url + path
                r, w = await ensure_conn()
                if not r or not w:
                    break

                # If we already have a working credential and auth challenge, construct auth header directly
                direct_auth_hdr = ""
                if cached_working_cred:
                    u_cached, p_cached = cached_working_cred
                    if "digest" in cached_auth_hdr_challenge.lower():
                        direct_auth_hdr = _build_digest_header(u_cached, p_cached, "DESCRIBE", url, cached_auth_hdr_challenge)
                    else:
                        token = base64.b64encode(f"{u_cached}:{p_cached}".encode()).decode()
                        direct_auth_hdr = f"Authorization: Basic {token}\r\n"

                # If we know the camera requires auth (from OPTIONS or previous 401) but haven't found working cred yet,
                # immediately try candidate credentials to avoid socket resets from unauthenticated requests
                if not cached_working_cred and cached_auth_hdr_challenge and not auth_exhausted:
                    authed = False
                    for u_item, p_item in active_creds[:6]:
                        headers_to_try = []
                        if "digest" in cached_auth_hdr_challenge.lower():
                            d_hdr = _build_digest_header(u_item, p_item, "DESCRIBE", url, cached_auth_hdr_challenge)
                            if d_hdr:
                                headers_to_try.append(d_hdr)
                        token = base64.b64encode(f"{u_item}:{p_item}".encode()).decode()
                        headers_to_try.append(f"Authorization: Basic {token}\r\n")

                        for auth_hdr in headers_to_try:
                            req_extra = f"{auth_hdr}Accept: application/sdp\r\n"
                            desc_auth = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                            cseq += 1
                            if not desc_auth:
                                try:
                                    w.close()
                                    await w.wait_closed()
                                except Exception:
                                    pass
                                writer = None
                                r, w = await ensure_conn()
                                if not r or not w:
                                    break
                                desc_auth = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                                cseq += 1

                            if "200 OK" in desc_auth and ("m=video" in desc_auth or "m=audio" in desc_auth or "v=0" in desc_auth):
                                auth_url = _format_rtsp_url(ip, port, path, u_item, p_item)
                                found_urls.append(auth_url)
                                cached_working_cred = (u_item, p_item)
                                result["credentials"] = {"user": u_item, "password": p_item}
                                if not result["sdp_info"]:
                                    result["sdp_info"] = desc_auth
                                authed = True

                                try:
                                    w.close()
                                    await w.wait_closed()
                                except Exception:
                                    pass
                                writer = None
                                break
                        if authed:
                            break

                    if authed:
                        if len(found_urls) >= 128:
                            break
                        continue
                    else:
                        # Credentials failed on this path; continue or mark exhausted if on main path
                        continue

                req_extra = f"{direct_auth_hdr}Accept: application/sdp\r\n" if direct_auth_hdr else "Accept: application/sdp\r\n"
                desc = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                cseq += 1

                # Reconnect on dropped socket
                if not desc:
                    try:
                        w.close()
                        await w.wait_closed()
                    except Exception:
                        pass
                    writer = None
                    r, w = await ensure_conn()
                    if not r or not w:
                        continue
                    desc = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                    cseq += 1

                if not result["brand"]:
                    brand = _detect_brand_from_rtsp_text(desc)
                    if brand:
                        result["brand"] = brand

                # 200 OK
                if "200 OK" in desc and ("m=video" in desc or "m=audio" in desc or "v=0" in desc):
                    if cached_working_cred:
                        u_c, p_c = cached_working_cred
                        found_urls.append(_format_rtsp_url(ip, port, path, u_c, p_c))
                    else:
                        found_urls.append(url)
                    if not result["sdp_info"]:
                        result["sdp_info"] = desc

                    # Disconnect socket so the next path is queried on a fresh connection.
                    # This prevents camera media servers (e.g. Hikvision Media Server V3.4.2)
                    # from latching the socket and echoing the previous channel's SDP on non-existent paths.
                    try:
                        w.close()
                        await w.wait_closed()
                    except Exception:
                        pass
                    writer = None

                    if len(found_urls) >= 128:
                        break
                    continue

                # If 401 or WWW-Authenticate header, handle authentication
                if ("401" in desc or "WWW-Authenticate" in desc) and not auth_exhausted:
                    # Update challenge info
                    cached_auth_hdr_challenge = desc
                    authed = False

                    # If we already have a working credential, only use that working credential!
                    if cached_working_cred:
                        cred_candidates = [cached_working_cred]
                    else:
                        cred_candidates = active_creds[:6]

                    for u_item, p_item in cred_candidates:
                        headers_to_try = []
                        if "digest" in desc.lower():
                            d_hdr = _build_digest_header(u_item, p_item, "DESCRIBE", url, desc)
                            if d_hdr:
                                headers_to_try.append(d_hdr)
                        token = base64.b64encode(f"{u_item}:{p_item}".encode()).decode()
                        headers_to_try.append(f"Authorization: Basic {token}\r\n")

                        for auth_hdr in headers_to_try:
                            req_extra = f"{auth_hdr}Accept: application/sdp\r\n"
                            desc_auth = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                            cseq += 1
                            if not desc_auth:
                                try:
                                    w.close()
                                    await w.wait_closed()
                                except Exception:
                                    pass
                                writer = None
                                r, w = await ensure_conn()
                                if not r or not w:
                                    break
                                desc_auth = await _rtsp_request(r, w, "DESCRIBE", url, cseq, req_extra, timeout=2.5)
                                cseq += 1

                            if "200 OK" in desc_auth and ("m=video" in desc_auth or "m=audio" in desc_auth or "v=0" in desc_auth):
                                auth_url = _format_rtsp_url(ip, port, path, u_item, p_item)
                                found_urls.append(auth_url)
                                cached_working_cred = (u_item, p_item)
                                result["credentials"] = {"user": u_item, "password": p_item}
                                if not result["sdp_info"]:
                                    result["sdp_info"] = desc_auth
                                authed = True

                                # Close socket so next path starts fresh
                                try:
                                    w.close()
                                    await w.wait_closed()
                                except Exception:
                                    pass
                                writer = None
                                break
                        if authed:
                            break

                    if authed:
                        if len(found_urls) >= 128:
                            break
                    else:
                        if not cached_working_cred:
                            # Candidate credentials all failed on challenged stream: avoid lockout
                            auth_exhausted = True
                        failed_auth_paths += 1
                        if failed_auth_paths >= 20:
                            break

            # Deduplicate preserving order
            seen = set()
            deduped = []
            for u in found_urls:
                if u not in seen:
                    seen.add(u)
                    deduped.append(u)

            result["rtsp_urls"] = deduped
            result["success"] = len(deduped) > 0

        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        if result["success"]:
            return result

    return result
