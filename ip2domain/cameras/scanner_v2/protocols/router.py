"""Router, gateway, and network device identification for Scanner v2."""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional, Tuple

import httpx

# Popular router brand patterns matching (title, Server header, WWW-Authenticate realm, body text)
ROUTER_BRAND_SIGNATURES = [
    ("MikroTik", [
        r"\bmikrotik\b", r"\brouteros\b", r"\bwebfig\b", r"routeros\s+router\s+configuration",
    ]),
    ("Keenetic", [
        r"\bkeenetic\b", r"\bndms\b", r"keenetic\s+web", r"keeneticos",
    ]),
    ("TP-Link", [
        r"\btp-link\b", r"\btplink\b", r"wireless\s+router\s+wr\d+", r"archer\s+[acx]\d+",
        r"deco\s+[mxe]\d+", r"loginrpm\.htm", r"tplinkwifi\.net",
    ]),
    ("ASUS", [
        r"\basuswrt\b", r"\basus\s+wireless\s+router\b", r"\brt-[a-z]{1,2}\d+\b",
        r"\baimesh\b", r"\basustek\b", r"asus\.com",
    ]),
    ("D-Link", [
        r"\bd-link\b", r"\bdlink\b", r"\bdir-\d+\b", r"\bdsl-\d+\b",
    ]),
    ("Huawei", [
        r"\bhuawei\b", r"\becholife\b", r"\bhg8\d+\b", r"huawei\s+home\s+gateway",
    ]),
    ("ZTE", [
        r"\bzte\b", r"\bzxhn\b", r"zte\s+corporation",
    ]),
    ("Cisco", [
        r"\bcisco\b", r"\blinksys\b", r"cisco\s+systems",
    ]),
    ("OpenWrt", [
        r"\bopenwrt\b", r"\bluci\b", r"\bdd-wrt\b", r"\bgargoyle\b",
    ]),
    ("Ubiquiti", [
        r"\bubiquiti\b", r"\bedgeos\b", r"\bairos\b", r"\bunifi\s+os\b", r"\bunifi\s+network\b",
    ]),
    ("pfSense", [
        r"\bpfsense\b", r"\bopnsense\b",
    ]),
    ("Netgear", [
        r"\bnetgear\b", r"\bnighthawk\b", r"\borbi\b",
    ]),
    ("Zyxel", [
        r"\bzyxel\b", r"\bzywall\b", r"\bkeenetic\b",
    ]),
    ("Tenda", [
        r"\btenda\b", r"tenda\s+wireless",
    ]),
    ("Mercusys", [
        r"\bmercusys\b",
    ]),
    ("Xiaomi", [
        r"\bmiwifi\b", r"\bmi\s+router\b", r"\bxiaomi\s+router\b",
    ]),
    ("Totolink", [
        r"\btotolink\b",
    ]),
]

GENERIC_ROUTER_KEYWORDS = [
    r"\bwireless\s+router\b",
    r"\bbroadband\s+router\b",
    r"\bwi-fi\s+router\b",
    r"\bhome\s+gateway\b",
    r"\bgpon\s+ont\b",
    r"\bepon\s+onu\b",
    r"\bdsl\s+modem\b",
    r"\bcable\s+modem\b",
    r"\baccess\s+point\b",
]


async def probe_winbox(ip: str, port: int = 8291, timeout: float = 2.0) -> bool:
    """Detect MikroTik RouterOS Winbox service on port 8291."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            # Send standard Winbox discovery / negotiation probe
            writer.write(b"\x00\x00\x00\x00")
            await asyncio.wait_for(writer.drain(), timeout=1.0)
            data = await asyncio.wait_for(reader.read(32), timeout=1.5)
            # MikroTik responds or holds valid connection
            return True
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return False


async def probe_router(
    ip: str,
    ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Identify router / gateway brand, model, realm, and web address."""
    result: Dict = {
        "success": False,
        "brand": "",
        "model": "",
        "title": "",
        "web_port": 0,
        "web_url": "",
        "device_category": "router",
        "auth_required": None,
        "protocols": [],
    }

    # 1. Check Winbox first if port 8291 is present
    if 8291 in ports:
        is_winbox = await probe_winbox(ip, 8291)
        if is_winbox:
            result.update({
                "success": True,
                "brand": "MikroTik",
                "model": "RouterOS",
                "web_port": 80 if 80 in ports else (443 if 443 in ports else 8291),
                "web_url": f"http://{ip}" if 80 in ports else f"winbox://{ip}:8291",
                "title": "MikroTik RouterOS (Winbox)",
                "protocols": ["winbox", "mikrotik_routeros"],
            })

    # 2. Check HTTP / HTTPS web interfaces
    web_candidates = [p for p in ports if p in {80, 443, 8080, 8443, 8081, 8181, 8880, 8888, 9443, 10443, 8000, 8008, 7547, 4567}]
    if not web_candidates:
        web_candidates = [p for p in ports if p not in {554, 555, 1935, 8291}]

    if not web_candidates:
        return result

    async with httpx.AsyncClient(verify=False, timeout=3.5, follow_redirects=True) as client:
        for port in web_candidates[:5]:
            schemes = ["https", "http"] if port in {443, 8443, 9443, 10443} else ["http", "https"]
            for scheme in schemes:
                target_url = f"{scheme}://{ip}:{port}/"
                try:
                    resp = await client.get(target_url, timeout=3.5)
                except Exception:
                    continue

                text = resp.text[:8192]
                server = resp.headers.get("server", "")
                www_auth = resp.headers.get("www-authenticate", "")
                title_m = re.search(r"<title[^>]*>([^<]{1,160})</title>", text, re.IGNORECASE)
                title = title_m.group(1).strip() if title_m else ""

                # Extract Basic Realm if present
                realm_m = re.search(r'realm=["\']([^"\']+)["\']', www_auth, re.IGNORECASE)
                realm = realm_m.group(1).strip() if realm_m else ""

                combined = f"{title} {server} {www_auth} {realm} {text[:1024]}".lower()

                # Check known router brands
                matched_brand = ""
                matched_model = ""
                for brand, patterns in ROUTER_BRAND_SIGNATURES:
                    if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
                        matched_brand = brand
                        break

                # Extract model from realm or title if available
                if matched_brand:
                    if realm and matched_brand.lower() in realm.lower():
                        matched_model = realm
                    elif title and matched_brand.lower() in title.lower():
                        matched_model = title
                    else:
                        matched_model = realm or title or f"{matched_brand} Router"

                # Check generic router keywords
                is_generic_router = False
                if not matched_brand:
                    for g_pat in GENERIC_ROUTER_KEYWORDS:
                        if re.search(g_pat, combined, re.IGNORECASE):
                            is_generic_router = True
                            matched_brand = "Generic Router"
                            matched_model = realm or title or "Broadband Router"
                            break

                if matched_brand or is_generic_router:
                    protocols = result.get("protocols", [])
                    if "http_router" not in protocols:
                        protocols.append("http_router")
                    result.update({
                        "success": True,
                        "brand": matched_brand or result.get("brand") or "Generic Router",
                        "model": matched_model or result.get("model") or "",
                        "title": title or realm or result.get("title") or f"{matched_brand} Web",
                        "web_port": port,
                        "web_url": f"{scheme}://{ip}:{port}/",
                        "auth_required": resp.status_code == 401 or bool(www_auth),
                        "protocols": protocols,
                    })
                    return result

    return result
