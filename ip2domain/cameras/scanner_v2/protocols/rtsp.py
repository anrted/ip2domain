"""Direct RTSP DESCRIBE probe for Camera Scanner v2.

Sends raw RTSP OPTIONS + DESCRIBE over TCP to detect live streams
and identify camera vendor from RTSP Server header.
Includes exhaustive path wordlist for all major camera manufacturers.
"""
from __future__ import annotations

import asyncio
import base64
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
    "/cam0/h264",
    "/cam1/h264",
    "/cam/h264",
    "/cam0/mjpeg",
    "/cam1/mjpeg",
    "/user=admin_password=_channel=1_stream=0.sdp",
    "/user=admin_password=_channel=1_stream=1.sdp",
    "/user=admin_password=_channel=0_stream=0.sdp",
    "/live.sdp",
    "/h264",
    "/h264.sdp",
    "/mpeg4",
]

# Hikvision / Ezviz / HiLook
_HIK_PATHS = [
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/201",
    "/Streaming/Channels/202",
    "/Streaming/Channels/1",
    "/Streaming/Channels/2",
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/ISAPI/Streaming/channels/101",
    "/PSIA/streaming/channels/101",
    "/PSIA/streaming/channels/102",
    "/PSIA/streaming/channels/1",
]

# Dahua / Imou / Lorex / Lechange / IC Realtime
_DAHUA_PATHS = [
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cam/realmonitor?channel=2&subtype=0",
    "/cam/realmonitor?channel=2&subtype=1",
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
    "/profile1/media.smp",
    "/profile2/media.smp",
    "/onvif/profile1/media.smp",
]

# Tiandy / Grandstream / Foscam / Generic / Other DVR
_GENERIC_PATHS = [
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
    "/live/ch0",
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
        f"User-Agent: CameraScanner/2.0\r\n"
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


def _build_digest_header(user: str, password: str, method: str, url: str, www_auth: str) -> str:
    """Build RFC 2617 RTSP Digest Authorization header from 401 WWW-Authenticate challenge."""
    realm_m = re.search(r'realm=["\']?([^"\',\r\n]+)["\']?', www_auth, re.IGNORECASE)
    nonce_m = re.search(r'nonce=["\']?([^"\',\r\n]+)["\']?', www_auth, re.IGNORECASE)
    if not realm_m or not nonce_m:
        return ""
    realm = realm_m.group(1).strip()
    nonce = nonce_m.group(1).strip()
    import hashlib
    def md5(s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()
    ha1 = md5(f"{user}:{realm}:{password}")
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
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=_TIMEOUT
            )
        except Exception:
            continue

        try:
            base_url = f"rtsp://{ip}:{port}"

            # 1. OPTIONS — confirm it's RTSP and extract vendor
            opts = await _rtsp_request(reader, writer, "OPTIONS", base_url + "/", 1, timeout=2.0)
            if "RTSP/1.0" not in opts and "Public:" not in opts and "Server:" not in opts:
                continue

            result["open_port"] = port

            brand = _detect_brand_from_rtsp_text(opts)
            if brand:
                result["brand"] = brand

            # Query compiled StrixCamDB for brand-specific paths
            db_brand_paths = _get_brand_rtsp_paths(result["brand"]) if result["brand"] else []

            # Select primary candidate paths based on vendor
            if result["brand"] == "Topsvision":
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
                probe_paths = db_brand_paths[:25]
            else:
                top_db = _get_compiled_db().get("top_rtsp", [])
                probe_paths = (top_db[:30] if top_db else []) or _GENERIC_PATHS[:30]

            found_urls: List[str] = []
            failed_auth_paths = 0
            cseq = 2

            for path in probe_paths:
                url = base_url + path
                # Try unauthenticated first
                desc = await _rtsp_request(reader, writer, "DESCRIBE", url, cseq, "Accept: application/sdp\r\n", timeout=0.8)
                cseq += 1

                if not result["brand"]:
                    brand = _detect_brand_from_rtsp_text(desc)
                    if brand:
                        result["brand"] = brand

                # 200 OK without auth
                if "200 OK" in desc and ("m=video" in desc or "m=audio" in desc or "v=0" in desc):
                    found_urls.append(url)
                    if not result["sdp_info"]:
                        result["sdp_info"] = desc
                    if len(found_urls) >= 4:
                        break
                    continue

                # If 401 or WWW-Authenticate header, try Digest and Basic credentials
                if "401" in desc or "WWW-Authenticate" in desc:
                    authed = False
                    for user, password in (credentials or [("admin", "admin"), ("admin", "12345"), ("admin", "123456"), ("admin", ""), ("root", "root"), ("root", "")])[:4]:
                        headers_to_try = []
                        if "digest" in desc.lower():
                            d_hdr = _build_digest_header(user, password, "DESCRIBE", url, desc)
                            if d_hdr:
                                headers_to_try.append(d_hdr)
                        token = base64.b64encode(f"{user}:{password}".encode()).decode()
                        headers_to_try.append(f"Authorization: Basic {token}\r\n")

                        for auth_hdr in headers_to_try:
                            req_extra = f"{auth_hdr}Accept: application/sdp\r\n"
                            desc_auth = await _rtsp_request(reader, writer, "DESCRIBE", url, cseq, req_extra, timeout=0.8)
                            cseq += 1
                            if "200 OK" in desc_auth and ("m=video" in desc_auth or "m=audio" in desc_auth or "v=0" in desc_auth):
                                auth_url = _format_rtsp_url(ip, port, path, user, password)
                                found_urls.append(auth_url)
                                result["credentials"] = {"user": user, "password": password}
                                if not result["sdp_info"]:
                                    result["sdp_info"] = desc_auth
                                authed = True
                                break
                        if authed:
                            break

                    if authed:
                        if len(found_urls) >= 4:
                            break
                    else:
                        failed_auth_paths += 1
                        if failed_auth_paths >= 10:
                            # 10 paths failed authentication with all given credentials -> camera likely locked
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
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        if result["success"]:
            return result

    return result
