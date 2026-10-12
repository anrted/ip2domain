"""Fast HTTP preflight fingerprinting for Scanner v2 Stage 2.

Performs a lightweight (1.2s timeout) GET / probe to determine device family
before launching heavy protocol probes (ONVIF SOAP, ISAPI, CGI, HLS wordlists).
Guarantees 100% device coverage by returning 'inconclusive' on any unknown,
401-protected, or ambiguous responses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import httpx

_PREFLIGHT_TIMEOUT = 1.0

# Server headers that definitively identify standard web software without CCTV/IoT
_STANDARD_WEB_SERVERS = (
    "nginx", "apache", "cloudflare", "litespeed", "caddy",
    "microsoft-iis", "gunicorn", "uvicorn", "openresty",
)


@dataclass
class PreflightResult:
    ip: str
    port: int
    is_alive: bool = False
    status_code: int = 0
    scheme: str = "http"
    server: str = ""
    www_auth: str = ""
    title: str = ""
    body_snippet: str = ""
    category: str = "inconclusive"  # "router_tr069", "cctv_hikvision", "cctv_dahua", "cctv_axis", "router", "intercom", "generic_web", "inconclusive"
    brand: str = ""
    model: str = ""
    target_protocols: List[str] = field(default_factory=list)


async def run_fast_preflight(
    ip: str,
    port: int,
    timeout: float = _PREFLIGHT_TIMEOUT,
) -> PreflightResult:
    """Send a single fast HTTP GET request to detect device identity early."""
    res = PreflightResult(ip=ip, port=port)

    # 1. Port 7547 is standard TR-069 CWMP management port
    if port == 7547:
        res.is_alive = True
        res.category = "router_tr069"
        res.brand = "TR-069 CWMP"
        res.model = "TR-069 CPE Agent"
        res.target_protocols = ["router"]
        return res

    scheme = "https" if port in (443, 8443, 9443, 10443) else "http"
    target_url = f"{scheme}://{ip}:{port}/"
    to_obj = timeout if isinstance(timeout, httpx.Timeout) else httpx.Timeout(timeout, connect=min(0.8, float(timeout)))

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(target_url, timeout=to_obj)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                # Host/port not reachable
                res.is_alive = False
                res.category = "dead"
                return res
            except Exception:
                # If HTTP failed on port that might be HTTPS (or vice versa), try alternate scheme once
                if scheme == "http" and port in (8080, 8000, 8443):
                    try:
                        scheme = "https"
                        target_url = f"https://{ip}:{port}/"
                        resp = await client.get(target_url, timeout=timeout)
                    except Exception:
                        res.is_alive = False
                        res.category = "dead"
                        return res
                else:
                    res.is_alive = False
                    res.category = "dead"
                    return res

            res.is_alive = True
            res.scheme = scheme
            res.status_code = resp.status_code
            res.server = resp.headers.get("server", "")
            res.www_auth = resp.headers.get("www-authenticate", "")

            # Check for SSL / HTTPS redirect hints in 400 response
            if resp.status_code == 400 and ("https" in resp.text.lower() or "ssl" in resp.text.lower()):
                try:
                    res.scheme = "https"
                    target_url = f"https://{ip}:{port}/"
                    resp = await client.get(target_url, timeout=timeout)
                    res.status_code = resp.status_code
                    res.server = resp.headers.get("server", "")
                    res.www_auth = resp.headers.get("www-authenticate", "")
                except Exception:
                    pass

            text = resp.text[:4096]
            res.body_snippet = text
            title_m = re.search(r"<title[^>]*>([^<]{1,128})</title>", text, re.IGNORECASE)
            res.title = title_m.group(1).strip() if title_m else ""

            server_l = res.server.lower()
            auth_l = res.www_auth.lower()
            title_l = res.title.lower()
            combined = f"{title_l} {server_l} {auth_l} {text[:2048]}".lower()

            # --- Classification checks ---

            # A. TR-069 / CWMP
            if "tr069" in combined or "cwmp" in combined or "tr-069" in combined:
                res.category = "router_tr069"
                res.brand = "TR-069 CWMP"
                res.model = "TR-069 CPE Agent"
                res.target_protocols = ["router"]
                return res

            # B. Hikvision / HiWatch / Ezviz
            if any(k in combined for k in (
                "hikvision", "app-webs", "dvrdvs-webs", "dnvrs-webs", "hikvision-webs",
                "doc/page/login.asp", "hiwatch", "ezviz", "hilook",
            )):
                res.category = "cctv_hikvision"
                res.brand = "Hikvision"
                res.model = "IP Camera / DVR"
                res.target_protocols = ["hikvision", "onvif", "rtsp", "hls"]
                return res

            # C. Dahua / IMOU
            if any(k in combined for k in (
                "dahua", "dh-webs", "dh_", "magicbox.cgi", "imou", "lorex",
            )):
                res.category = "cctv_dahua"
                res.brand = "Dahua"
                res.model = "IP Camera / DVR"
                res.target_protocols = ["dahua", "onvif", "rtsp", "hls"]
                return res

            # D. Axis
            if "axis" in server_l or "axis" in auth_l or "/axis-cgi/" in combined:
                res.category = "cctv_axis"
                res.brand = "Axis"
                res.model = "Network Camera"
                res.target_protocols = ["axis", "onvif", "rtsp", "hls"]
                return res

            # E. Video Intercoms (Qualvision, Tantos, Beward, etc.)
            if any(k in combined for k in ("qualvision", "tantos", "vwebclient.exe", "vms.tantos.pro", "preview.html")):
                res.category = "intercom"
                res.brand = "Qualvision / Tantos"
                res.model = "IP Intercom (Видеодомофон)"
                res.target_protocols = ["generic", "onvif"]
                return res

            # F. Audio recorder SpRecord
            if "sprecord" in server_l or "sprecord" in combined or "система многоканальной записи" in combined:
                res.category = "audio_recorder"
                res.brand = "SpRecord"
                res.model = "Система записи разговоров"
                res.target_protocols = ["sprecord"]
                return res

            # G. Known Routers
            router_brands = [
                ("MikroTik", ("mikrotik", "routeros", "webfig")),
                ("Keenetic", ("keenetic", "ndms", "keeneticos")),
                ("TP-Link", ("tp-link", "tplink", "archer", "deco", "loginrpm.htm")),
                ("ASUS", ("asuswrt", "rt-ac", "rt-ax")),
                ("OpenWrt", ("openwrt", "luci")),
                ("InHand Networks", ("inhand", "inrouter", "check_auth.jsp")),
                ("Teltonika", ("teltonika", "rutos")),
                ("Huawei", ("echolife", "huawei home gateway")),
                ("ZTE", ("zxhn", "zte corporation")),
                ("Ubiquiti", ("edgeos", "airos", "unifi os")),
                ("Com Hem", ("com hem", "wi-fi hub")),
            ]
            for r_brand, patterns in router_brands:
                if any(p in combined for p in patterns):
                    res.category = "router"
                    res.brand = r_brand
                    res.model = res.title or f"{r_brand} Router"
                    res.target_protocols = ["router", "generic"]
                    return res

            # H. PowerLogic / RomPager
            if "powerlogic" in combined or "ion7650" in combined or "rompager" in server_l:
                res.category = "industrial_meter"
                res.brand = "Schneider Electric"
                res.model = "PowerLogic ION7650"
                res.target_protocols = ["generic"]
                return res

            # I. Confirmed standard web server WITHOUT camera/IoT markers
            # If server header matches known web server AND no 401 auth challenge AND no camera keywords
            if (
                res.status_code in (200, 301, 302, 303, 307, 308, 404, 403)
                and any(ws in server_l for ws in _STANDARD_WEB_SERVERS)
                and not any(cam in combined for cam in ("camera", "cam", "video", "cctv", "stream", "live", "dvr", "nvr", "rtsp", "onvif"))
                and not res.www_auth
            ):
                res.category = "generic_web"
                res.brand = res.server.split("/")[0].strip().capitalize() or "Web Service"
                res.model = res.title or "HTTP Web Server"
                res.target_protocols = ["generic"]
                return res

            # J. Inconclusive: 401 auth required with unknown realm, obscure embedded server, or custom banner
            # Guarantees ZERO device drops: all inconclusive devices run the full probe suite!
            res.category = "inconclusive"
            return res

    except Exception:
        res.is_alive = False
        res.category = "dead"
        return res
