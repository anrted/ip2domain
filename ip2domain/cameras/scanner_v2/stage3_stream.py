"""Stage 3: Stream verification and frame capture for Camera Scanner v2.

Uses ffmpeg to capture a single frame from any stream type:
  RTSP, HLS, MJPEG, RTMP, UDP RTP
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

from .models import CameraResult, StreamInfo

logger = logging.getLogger(__name__)

_FFMPEG = shutil.which("ffmpeg") or "ffmpeg"
_FRAME_TIMEOUT = 8.0

# ffmpeg flags by stream type (timeout in microseconds: 5,000,000 = 5s)
_FFMPEG_ARGS = {
    "rtsp": [
        "-rtsp_transport", "tcp",
        "-timeout", "5000000",
        "-analyzeduration", "2000000",
        "-probesize", "1000000",
    ],
    "rtsp_udp": [
        "-rtsp_transport", "udp",
        "-timeout", "5000000",
        "-analyzeduration", "2000000",
    ],
    "hls": [
        "-protocol_whitelist", "http,https,tcp,tls,file,crypto",
    ],
    "mjpeg": [],
    "rtmp": [
        "-timeout", "5",
    ],
    "default": [],
}


def _capture_path(capture_dir: Path, stream_url: str) -> Path:
    url_hash = hashlib.md5(stream_url.encode()).hexdigest()[:12]
    return capture_dir / f"v2_{url_hash}.jpg"


def _format_input_url(stream_url: str, credentials: Optional[dict] = None) -> str:
    """Ensure credentials are in the URL for RTSP/RTMP if available."""
    if not stream_url:
        return ""
    if "@" in stream_url:
        return stream_url
    if credentials and credentials.get("user") and "://" in stream_url:
        user = credentials["user"]
        password = credentials.get("password", "")
        proto_end = stream_url.index("://") + 3
        proto = stream_url[:proto_end]
        rest = stream_url[proto_end:]
        u = urllib.parse.quote(user, safe="")
        p = urllib.parse.quote(password, safe="")
        return f"{proto}{u}:{p}@{rest}"
    return stream_url


async def capture_stream_frame(
    stream_url: str,
    stream_type: str,
    capture_dir: Path,
    credentials: Optional[dict] = None,
) -> Tuple[bool, str, str, int, int]:
    """Capture a single frame from the given stream URL using ffmpeg.

    Returns: (success, screenshot_path, codec, width, height)
    """
    if not shutil.which("ffmpeg"):
        return False, "", "", 0, 0

    capture_dir.mkdir(parents=True, exist_ok=True)
    out_path = _capture_path(capture_dir, stream_url)

    input_url = _format_input_url(stream_url, credentials)
    stype_key = stream_type if stream_type in _FFMPEG_ARGS else "default"
    extra_args = _FFMPEG_ARGS[stype_key]

    cmd = (
        [_FFMPEG, "-y", "-nostdin", "-hide_banner"]
        + extra_args
        + ["-i", input_url,
           "-frames:v", "1",
           "-q:v", "3",
           "-vf", "scale=iw*min(640/iw\\,480/ih):ih*min(640/iw\\,480/ih)",
           "-update", "1",
           str(out_path)]
    )

    codec, width, height = "", 0, 0
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_FRAME_TIMEOUT)
        stderr_text = (stderr or b"").decode(errors="ignore")

        if out_path.exists() and out_path.stat().st_size > 500:
            import re
            video_m = re.search(r"Video: (\w+)[^,]*,\s*[^,]+,\s*(\d+)x(\d+)", stderr_text)
            if video_m:
                codec = video_m.group(1).upper()
                width = int(video_m.group(2))
                height = int(video_m.group(3))
            return True, str(out_path), codec, width, height

    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.communicate()
        except Exception:
            pass
        logger.debug("[v2 Stage3] Frame capture timed out for %s", stream_url)
    except Exception as exc:
        logger.debug("[v2 Stage3] Frame capture error for %s: %s", stream_url, exc)

    return False, "", "", 0, 0


async def _download_http_snapshot(
    url: str,
    capture_dir: Path,
    credentials: Optional[dict] = None,
) -> Optional[str]:
    """Download JPEG snapshot from HTTP camera and save locally."""
    import httpx
    capture_dir.mkdir(parents=True, exist_ok=True)
    out_path = _capture_path(capture_dir, url)

    auth = None
    if credentials and credentials.get("user"):
        auth = (credentials["user"], credentials.get("password", ""))

    try:
        async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=True) as client:
            resp = await client.get(url, auth=auth)
            if resp.status_code == 200 and resp.content and (
                resp.content[:3] == b"\xff\xd8\xff"
                or "image" in resp.headers.get("content-type", "").lower()
            ):
                out_path.write_bytes(resp.content)
                return str(out_path)
    except Exception as exc:
        logger.debug("[v2 Stage3] Snapshot download failed for %s: %s", url, exc)
    return None


async def verify_camera_streams(
    camera: CameraResult,
    capture_dir: Path,
    max_streams_to_try: int = 6,
) -> int:
    """Verify streams for a single CameraResult and capture frames for valid streams.

    Downloads HTTP snapshots and runs ffmpeg for RTSP/MJPEG/HLS streams.
    Preserves all discovered streams and prioritizes verified ones.
    Returns the count of verified streams.
    """
    verified_streams = []

    # 1. Process HTTP snapshots, WebRTC, and MJPEG streams
    for stream in list(camera.streams):
        if stream.stream_type == "http_snapshot":
            if not stream.screenshot_path:
                path = await _download_http_snapshot(stream.url, capture_dir, camera.credentials)
                if path:
                    stream.screenshot_path = path
                    stream.verified = True
            if stream.screenshot_path or stream.verified:
                verified_streams.append(stream)
        elif stream.stream_type == "mjpeg":
            if not stream.screenshot_path:
                ok, path, codec, w, h = await capture_stream_frame(
                    stream_url=stream.url,
                    stream_type="mjpeg",
                    capture_dir=capture_dir,
                    credentials=camera.credentials,
                )
                if ok:
                    stream.screenshot_path = path
                    stream.verified = True
                    stream.codec = codec
                    stream.width = w
                    stream.height = h
            verified_streams.append(stream)
        elif stream.verified and stream not in verified_streams:
            verified_streams.append(stream)

    # 2. Test unverified streams (RTSP / RTMP / HLS)
    unverified_streams = [s for s in camera.streams if not s.verified and s not in verified_streams]
    streams_to_test = unverified_streams[:max_streams_to_try]

    for stream in streams_to_test:
        ok, path, codec, w, h = await capture_stream_frame(
            stream_url=stream.url,
            stream_type=stream.stream_type,
            capture_dir=capture_dir,
            credentials=camera.credentials,
        )
        if ok:
            stream.verified = True
            stream.screenshot_path = path
            stream.codec = codec
            stream.width = w
            stream.height = h
            stream.resolution = f"{w}x{h}" if w and h else ""
            verified_streams.append(stream)
            # Once we found a confirmed working stream for this camera, prioritize it
            break

    # 3. Sort streams: confirmed screenshots first, then verified, then RTSP, then rest
    def _stream_sort_key(s):
        score = 0
        if getattr(s, "screenshot_path", ""):
            score += 1000
        if getattr(s, "verified", False):
            score += 500
        if getattr(s, "width", 0) and getattr(s, "height", 0):
            score += min(100, (s.width * s.height) // 20000)
        if getattr(s, "stream_type", "") == "rtsp":
            score += 50
        return score

    camera.streams.sort(key=_stream_sort_key, reverse=True)
    return len([s for s in camera.streams if s.verified or s.screenshot_path])



