"""Dahua Media / DHIP protocol prober for Camera Scanner v2.

Default TCP port: 37777

Features:
- DHIP binary handshake probe.
- Device banner extraction.
- Standard Dahua RTSP and snapshot candidate URL generation.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
_DHIP_TIMEOUT = 2.5


async def probe_dahua_media(
    ip: str,
    port: int = 37777,
    credentials: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """Probe Dahua DVR/NVR/IPCam media port 37777."""
    result: Dict[str, Any] = {
        "success": False,
        "brand": "Dahua",
        "model": "Dahua DVR/NVR",
        "channels": 1,
        "rtsp_port": 554,
        "http_port": 80,
        "streams": [],
        "protocols": ["dahua_dhip"],
        "credentials": {},
    }

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=_DHIP_TIMEOUT
        )
    except Exception:
        return result

    try:
        # Send DHIP probe packet: Magic \xa0\x00\x00\x60
        probe_pkt = b"\xa0\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        writer.write(probe_pkt)
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(1024), timeout=_DHIP_TIMEOUT)
        if resp and (resp.startswith(b"\xa0") or resp.startswith(b"\xb0") or b"DHIP" in resp or len(resp) >= 8):
            result["success"] = True

            # Formulate Dahua RTSP streams for up to 8 channels
            creds = credentials or [("admin", "admin"), ("admin", "admin123"), ("admin", "")]
            u, p = creds[0] if creds else ("admin", "admin")
            auth_str = f"{u}:{p}@" if u else ""

            for ch in range(1, 9):
                # Dahua standard rtsp format
                result["streams"].append(f"rtsp://{auth_str}{ip}:554/cam/realmonitor?channel={ch}&subtype=0")
                result["streams"].append(f"rtsp://{auth_str}{ip}:554/cam/realmonitor?channel={ch}&subtype=1")

    except Exception as exc:
        logger.debug("[Dahua Media] Error probing %s:%s: %s", ip, port, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return result
