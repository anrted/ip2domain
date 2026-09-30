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
                        })
                        return result
                except Exception:
                    continue
    return result
