"""WebRTC and WHEP (WebRTC HTTP Egress Protocol) probe for Camera Scanner v2.

Detects modern IP cameras, media gateways (go2rtc, MediaMTX), and WHEP endpoints.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

_WHEP_PATHS = [
    "/api/whep",
    "/whep",
    "/api/whip",
    "/whip",
    "/api/webrtc",
    "/rtc/v1/whep",
    "/api/streams",
    "/api/version",
]


async def probe_webrtc(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe HTTP/HTTPS endpoints for WebRTC/WHEP capabilities.

    Returns: success, brand, model, streams, http_port, protocols
    """
    result = {
        "success": False,
        "brand": "",
        "model": "",
        "webrtc_urls": [],
        "http_port": 0,
        "protocols": [],
    }
    if not candidate_ports:
        return result

    # Check ports commonly serving WebRTC/WHEP (80, 8080, 1984, 8554, 8889, 7001)
    ports_to_check = [p for p in candidate_ports if p in {80, 8080, 1984, 8554, 8889, 7001, 8000, 5000}] or candidate_ports[:3]

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, follow_redirects=True) as client:
        for port in ports_to_check:
            base = f"http://{ip}:{port}"
            for user, password in credentials[:2]:
                auth = (user, password) if user else None

                # 1. Check go2rtc / MediaMTX API /api/streams
                try:
                    r = await client.get(f"{base}/api/streams", auth=auth, timeout=_TIMEOUT)
                    if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                        try:
                            data = r.json()
                            if isinstance(data, dict) and data:
                                stream_names = list(data.keys())
                                result["success"] = True
                                result["brand"] = "go2rtc / MediaMTX Gateway"
                                result["http_port"] = port
                                result["protocols"] = ["webrtc", "whep"]
                                for sname in stream_names[:6]:
                                    result["webrtc_urls"].append(f"{base}/api/whep?src={sname}")
                                    result["webrtc_urls"].append(f"{base}/api/stream.mp4?src={sname}")
                                return result
                        except Exception:
                            pass
                except Exception:
                    pass

                # 2. Check WHEP endpoints via OPTIONS / POST
                for path in _WHEP_PATHS:
                    try:
                        r = await client.options(base + path, auth=auth, timeout=2.0)
                        link_hdr = r.headers.get("link", "") or r.headers.get("access-control-allow-methods", "")
                        if r.status_code in (200, 204, 405) and ("POST" in link_hdr or "whep" in link_hdr.lower() or "sdp" in r.text.lower()):
                            result["success"] = True
                            result["brand"] = "WHEP / WebRTC Camera"
                            result["http_port"] = port
                            result["protocols"] = ["webrtc", "whep"]
                            result["webrtc_urls"].append(base + path)
                            return result
                    except Exception:
                        pass

    return result
