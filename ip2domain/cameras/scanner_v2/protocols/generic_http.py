"""Legacy HTTP camera fingerprinting, isolated from probe orchestration."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

import httpx

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
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "tl-sc": "TP-Link",
    "mag_52": "TP-Link",
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
            # 1. Specialized TP-Link TL-SC camera metadata probe (/prod)
            try:
                prod_resp = await client.get(f"http://{ip}:{port}/prod", timeout=2.0)
                if prod_resp.status_code == 200 and "initProd" in prod_resp.text:
                    p_text = prod_resp.text
                    nbr_m = re.search(r'initProdNbr\s*=\s*["\']([^"\']+)["\']', p_text)
                    name_m = re.search(r'initProdFullName\s*=\s*["\']([^"\']+)["\']', p_text)
                    model_val = nbr_m.group(1).strip() if nbr_m else "TL-SC Camera"
                    title_val = name_m.group(1).strip() if name_m else "Wireless Surveillance Camera"
                    result.update({
                        "success": True,
                        "brand": "TP-Link",
                        "model": model_val,
                        "title": title_val,
                        "http_port": port,
                        "device_category": "camera",
                        "web_url": f"http://{ip}:{port}/",
                        "snapshot_path": "/jpg/image.jpg",
                        "rtsp_path": "/video.mp4",
                    })
                    # Probe root to see if credentials or auth is needed
                    try:
                        r0 = await client.get(f"http://{ip}:{port}/", timeout=2.0)
                        if r0.status_code == 401:
                            result["auth_required"] = True
                            for u, p in credentials[:2]:
                                if not u:
                                    continue
                                r_auth = await client.get(f"http://{ip}:{port}/jpg/image.jpg", auth=(u, p), timeout=2.0)
                                if r_auth.status_code == 200:
                                    result["credentials"] = {"user": u, "password": p}
                                    result["auth_required"] = False
                                    break
                    except Exception:
                        pass
                    return result
            except Exception:
                pass

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

                    # Check TP-Link realm signature (mag_52, mag_*)
                    if re.search(r'realm=["\']mag_\d+["\']', www_auth, re.IGNORECASE):
                        result.update({
                            "success": True,
                            "brand": "TP-Link",
                            "model": "TL-SC Camera",
                            "title": title or "Wireless Surveillance Camera",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"http://{ip}:{port}/",
                            "auth_required": resp.status_code == 401,
                            "snapshot_path": "/jpg/image.jpg",
                            "rtsp_path": "/video.mp4",
                        })
                        if auth and resp.status_code == 200:
                            result["credentials"] = {"user": user, "password": password}
                        return result

                    brand = ""
                    for keyword, brand_name in _CAMERA_BRANDS.items():
                        # Strict regex word boundary match to avoid false positives (e.g. 'rvi' in 'service' or 'dvr' in words)
                        if re.search(rf"\b{re.escape(keyword)}\b", combined, re.IGNORECASE):
                            brand = brand_name
                            break

                    # Require explicit camera / surveillance context if no specific brand matched
                    has_cam_context = bool(
                        re.search(r"\b(rtsp|ipcam|ipcamera|webcam|cctv|dvr|nvr|onvif|netcam)\b", combined, re.IGNORECASE)
                        or (("camera" in combined or "surveillance" in combined) and any(w in combined for w in ("login", "channel", "live", "video-stream", "view")))
                    )

                    if brand or has_cam_context:
                        result.update({
                            "success": True,
                            "brand": brand or "Generic IPCam",
                            "title": title,
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"http://{ip}:{port}/",
                        })
                        return result

                    # Check router signatures
                    from .router import ROUTER_BRAND_SIGNATURES, GENERIC_ROUTER_KEYWORDS
                    for r_brand, patterns in ROUTER_BRAND_SIGNATURES:
                        if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
                            result.update({
                                "success": True,
                                "brand": r_brand,
                                "model": title or f"{r_brand} Router",
                                "title": title,
                                "http_port": port,
                                "device_category": "router",
                                "web_url": f"http://{ip}:{port}/",
                            })
                            return result

                    if any(re.search(pat, combined, re.IGNORECASE) for pat in GENERIC_ROUTER_KEYWORDS):
                        result.update({
                            "success": True,
                            "brand": "Generic Router",
                            "model": title or "Broadband Router",
                            "title": title,
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"http://{ip}:{port}/",
                        })
                        return result

                    # Generic web device fallback (never drop active HTTP services)
                    server_label = (server.split("/")[0].strip() if server else "").strip()
                    result.update({
                        "success": True,
                        "brand": "Generic Web Device",
                        "model": server_label or "Web Service",
                        "title": title or f"HTTP {resp.status_code}",
                        "http_port": port,
                        "device_category": "generic_web",
                        "web_url": f"http://{ip}:{port}/",
                    })
                    return result
                except Exception:
                    continue
    return result


probe_generic_http = _probe_generic_http

