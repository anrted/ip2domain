"""HLS and MJPEG HTTP probe for Camera Scanner v2.

Checks common paths for JPEG snapshots, MJPEG streams, and HLS manifests.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 3.0

_SNAPSHOT_PATHS = [
    "/snap.jpg?JpegCam=0",
    "/snap.jpg?JpegSize=XL",
    "/snap.jpg",
    "/snap.jpg?usr=admin&pwd=",
    "/snap.jpg?JpegSize=M",
    "/snap.jpg?JpegCam=1",
    "/snap.jpg?JpegCam=80",
    "/snapshot.jpg?user=admin&pwd=&strm=0",
    "/snapshot.jpg?user=admin&pwd=",
    "/snapshot.jpg",
    "/tmpfs/auto.jpg",
    "/tmpfs/snap.jpg",
    "/snapshot.cgi",
    "/img/snapshot.cgi?size=2",
    "/cgi-bin/snapshot.cgi",
    "/jpg/image.jpg",
    "/image.jpg",
    "/cgi-bin/jpg/image.cgi",
    "/cgi-bin/camera",
    "/webcapture.jpg",
    "/onvif-http/snapshot",
    "/dms?nowprofileid=1",
    "/action/snap",
    "/cgi-bin/viewer/video.jpg",
    "/videostream.cgi?rate=0&resolution=640x480",
]

_MJPEG_PATHS = [
    "/video.mjpg", "/videostream.cgi",
    "/cgi-bin/mjpg/video.cgi", "/cgi-bin/videostream.cgi",
    "/axis-cgi/mjpg/video.cgi", "/stream/video.mjpeg",
    "/mjpeg/video.mjpeg",
]

_HLS_PATHS = [
    "/live/index.m3u8", "/hls/live.m3u8", "/stream.m3u8",
    "/stream/live.m3u8", "/live.m3u8", "/api/streams/main.m3u8",
    "/hls/stream.m3u8", "/live/stream.m3u8",
]


def _is_jpeg(content: bytes) -> bool:
    return bool(content) and content[:3] == b"\xff\xd8\xff"


def _is_hls(content: bytes) -> bool:
    return bool(content) and b"#EXTM3U" in content[:64]


async def probe_hls_mjpeg(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe HTTP endpoints for MJPEG, HLS, and JPEG snapshots.

    Returns: success, snapshot_url, mjpeg_url, hls_url, http_port, snapshot_bytes
    """
    result = {
        "success": False, "snapshot_url": "", "mjpeg_url": "", "hls_url": "",
        "http_port": 0, "credentials": {}, "snapshot_bytes": None,
    }
    if not candidate_ports:
        return result

    _CHECK_TIMEOUT = 1.5   # root check — fast fail for dead ports
    _PATH_TIMEOUT  = 3.0   # snapshot/HLS paths — some slow devices need this

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for port in candidate_ports[:3]:  # max 3 HTTP ports
            base = f"http://{ip}:{port}"

            # Step 1: Quick root check — confirm port is alive and find working credential
            working_auth = None
            found_cred = None
            for user, password in credentials[:3]:
                auth = (user, password) if user else None
                try:
                    resp = await client.get(base + "/", auth=auth, timeout=_CHECK_TIMEOUT)
                    if resp.status_code == 200:
                        working_auth = auth
                        found_cred = {"user": user, "password": password}
                        break
                    elif resp.status_code == 401:
                        continue
                    elif resp.status_code in (404, 302, 301, 403):
                        working_auth = auth
                        found_cred = {"user": user, "password": password}
                        break
                except Exception:
                    break  # Port not responding — skip

            if working_auth is None and found_cred is None:
                continue

            # Step 2: Try JPEG snapshot paths with the working credential
            for path in _SNAPSHOT_PATHS:
                try:
                    resp = await client.get(base + path, auth=working_auth, timeout=_PATH_TIMEOUT)
                    if resp.status_code == 200 and _is_jpeg(resp.content):
                        result.update({
                            "success": True, "snapshot_url": base + path,
                            "http_port": port,
                            "credentials": found_cred or {},
                            "snapshot_bytes": resp.content,
                        })
                        for mp in _MJPEG_PATHS:
                            try:
                                async with client.stream("GET", base + mp, auth=working_auth, timeout=_CHECK_TIMEOUT) as mr:
                                    if mr.status_code == 200 and "image/jpeg" in mr.headers.get("content-type", "").lower():
                                        result["mjpeg_url"] = base + mp
                                        break
                            except Exception:
                                pass
                        for hp in _HLS_PATHS:
                            try:
                                hr = await client.get(base + hp, auth=working_auth, timeout=_CHECK_TIMEOUT)
                                if hr.status_code == 200 and _is_hls(hr.content):
                                    result["hls_url"] = base + hp
                                    break
                            except Exception:
                                pass
                        return result
                except Exception:
                    continue

            # Step 3: Try HLS paths
            for path in _HLS_PATHS:
                try:
                    resp = await client.get(base + path, auth=working_auth, timeout=_PATH_TIMEOUT)
                    if resp.status_code == 200 and _is_hls(resp.content):
                        result.update({
                            "success": True, "hls_url": base + path,
                            "http_port": port,
                            "credentials": found_cred or {},
                        })
                        return result
                except Exception:
                    continue

    return result
