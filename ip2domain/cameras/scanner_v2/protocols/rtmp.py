"""RTMP probe for Camera Scanner v2.

Performs RTMP handshake to confirm an RTMP server is present
and generates candidate RTMP stream URLs.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

# RTMP C0+C1 handshake: version byte (0x03) + 1536 bytes of time+zeros
_RTMP_C0C1 = bytes([0x03]) + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 1528

_RTMP_PATHS = [
    "/live",
    "/live/ch0",
    "/live/ch1",
    "/live/main",
    "/live/sub",
    "/live/stream",
    "/stream",
    "/stream1",
    "/app/live",
    "/flv",
]


async def probe_rtmp(ip: str, rtmp_ports: List[int]) -> Dict:
    """Send RTMP handshake to confirm RTMP server presence.

    Returns: success, open_port, rtmp_url, rtmp_urls
    """
    result = {"success": False, "open_port": 0, "rtmp_url": "", "rtmp_urls": []}
    if not rtmp_ports:
        return result

    for port in rtmp_ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=_TIMEOUT
            )
        except Exception:
            continue

        try:
            writer.write(_RTMP_C0C1)
            await writer.drain()
            # Wait for S0+S1+S2 (1 + 1536 + 1536 = 3073 bytes)
            data = await asyncio.wait_for(reader.read(3073), timeout=2.0)
            # RTMP S0 should be 0x03
            if data and data[0] == 0x03 and len(data) >= 1537:
                result["success"] = True
                result["open_port"] = port
                result["rtmp_url"] = f"rtmp://{ip}:{port}/live"
                result["rtmp_urls"] = [f"rtmp://{ip}:{port}{p}" for p in _RTMP_PATHS]
                return result
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return result
