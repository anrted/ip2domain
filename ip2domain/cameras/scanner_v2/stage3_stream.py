"""Stage 3: Stream verification and frame capture for Camera Scanner v2.

Uses ffmpeg to capture a single frame from any stream type:
  RTSP, HLS, MJPEG, RTMP, UDP RTP
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import uuid
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
        "-stimeout", "5000000",
        "-timeout", "5000000",
        "-analyzeduration", "1000000",
        "-probesize", "500000",
        "-fflags", "nobuffer",
        "-flags", "low_delay",
    ],
    "rtsp_udp": [
        "-rtsp_transport", "udp",
        "-timeout", "5000000",
        "-analyzeduration", "1000000",
        "-probesize", "500000",
        "-fflags", "nobuffer",
        "-flags", "low_delay",
    ],
    "hls": [
        "-protocol_whitelist", "http,https,tcp,tls,file,crypto",
        "-timeout", "5000000",
    ],
    "mjpeg": [
        "-timeout", "5000000",
    ],
    "rtmp": ["-rw_timeout", "5000000"],
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


def _valid_frame(path: Path) -> bool:
    try:
        from PIL import Image
        with Image.open(path) as frame:
            frame.load()
            return frame.width > 0 and frame.height > 0
    except (OSError, ValueError):
        return False


async def capture_stream_frame(
    stream_url: str,
    stream_type: str,
    capture_dir: Path,
    credentials: Optional[dict] = None,
) -> Tuple[bool, str, str, int, int, str]:
    """Capture a single frame from the given stream URL using ffmpeg.

    For RTSP streams, tries TCP transport first, then HTTP tunneling, then UDP transport.
    Returns: (success, screenshot_path, codec, width, height, transport)
    """
    if not shutil.which("ffmpeg"):
        return False, "", "", 0, 0, ""

    capture_dir.mkdir(parents=True, exist_ok=True)
    final_path = _capture_path(capture_dir, stream_url)

    if stream_type == "http_snapshot":
        local_path = await _download_http_snapshot(stream_url, capture_dir, credentials)
        if local_path and _valid_frame(Path(local_path)):
            w, h = 0, 0
            try:
                from PIL import Image
                with Image.open(local_path) as frame:
                    w, h = frame.size
            except Exception:
                pass
            return True, str(local_path), "JPEG", w, h, "http"
        return False, "", "", 0, 0, ""

    input_url = _format_input_url(stream_url, credentials)
    stype_key = stream_type if stream_type in _FFMPEG_ARGS else "default"

    # For RTSP, try TCP first, then fall back to UDP (skip obsolete rtsp_http)
    attempts = [stype_key]
    if stream_type in ("rtsp", "rtsps"):
        attempts = ["rtsp", "rtsp_udp"]

    attempt_transport_map = {
        "rtsp": "tcp",
        "rtsp_udp": "udp",
    }

    for attempt_key in attempts:
        # Unique output prevents old frames and concurrent requests from
        # being mistaken for this attempt's result.
        out_path = capture_dir / f".capture_{uuid.uuid4().hex}.jpg"
        proc = None
        extra_args = _FFMPEG_ARGS.get(attempt_key, [])
        cmd = (
            [_FFMPEG, "-y", "-nostdin", "-hide_banner", "-threads", "1"]
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

            if proc.returncode == 0 and _valid_frame(out_path):
                video_m = re.search(r"Video: (\w+)([^\n]*)", stderr_text)
                if video_m:
                    codec = video_m.group(1).upper()
                    dimensions = re.search(r"\b([1-9]\d{0,5})x([1-9]\d{0,5})\b", video_m.group(2))
                    if dimensions:
                        width, height = map(int, dimensions.groups())
                if not width or not height:
                    from PIL import Image
                    with Image.open(out_path) as frame:
                        width, height = frame.size
                out_path.replace(final_path)
                transport = attempt_transport_map.get(attempt_key, "tcp")
                return True, str(final_path), codec, width, height, transport

            # Fail-fast on fatal RTSP errors (401, 404, 403, connection refused)
            # Retrying UDP on a path that returned 401 Unauthorized or 404 Not Found is pointless
            if proc.returncode != 0:
                err_lower = stderr_text.lower()
                is_fatal = (
                    "401 unauthorized" in err_lower
                    or "404 not found" in err_lower
                    or "404 stream not found" in err_lower
                    or "403 forbidden" in err_lower
                    or "connection refused" in err_lower
                    or "method not allowed" in err_lower
                    or "authentication error" in err_lower
                )
                if is_fatal:
                    break

        except asyncio.TimeoutError:
            logger.debug("[v2 Stage3] Frame capture timed out (%s)", attempt_key)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("[v2 Stage3] Frame capture error (%s): %s", attempt_key, type(exc).__name__)
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.communicate()
            out_path.unlink(missing_ok=True)

    return False, "", "", 0, 0, ""


def _build_safe_snapshot_url(raw_url: str) -> Optional[str]:
    """Validate snapshot URL and reconstruct from sanitized components to prevent SSRF."""
    if not raw_url or not isinstance(raw_url, str):
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme not in ("http", "https"):
            return None
        host = parsed.hostname
        if not host:
            return None
        host_clean = host.strip("[]").lower()
        if host_clean in ("metadata.google.internal", "metadata", "instance-data", "169.254.169.254", "localhost"):
            return None
        try:
            ip_obj = ipaddress.ip_address(host_clean)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return None
            if ip_obj.version == 4:
                n = int(ip_obj)
                clean_host = f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
            else:
                clean_host = f"[{ip_obj}]"
        except ValueError:
            if not re.fullmatch(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?$", host_clean):
                return None
            if any(b in host_clean for b in ("metadata", "internal", "localhost")):
                return None
            clean_host = host_clean

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        clean_port = int(port) if 1 <= int(port) <= 65535 else (443 if parsed.scheme == "https" else 80)

        clean_path = parsed.path if parsed.path.startswith("/") else f"/{parsed.path}"
        if not re.fullmatch(r"^/[a-zA-Z0-9/_.\-~%]*$", clean_path):
            return None

        reconstructed = f"{parsed.scheme}://{clean_host}:{clean_port}{clean_path}"
        if parsed.query and re.fullmatch(r"^[a-zA-Z0-9/_.\-~%=&+]*$", parsed.query):
            reconstructed += f"?{parsed.query}"
        return reconstructed
    except Exception:
        return None


async def _download_http_snapshot(
    url: str,
    capture_dir: Path,
    credentials: Optional[dict] = None,
) -> Optional[str]:
    """Download JPEG snapshot from HTTP camera and save locally."""
    safe_url = _build_safe_snapshot_url(url)
    if not safe_url:
        logger.debug("[v2 Stage3] Prohibited or invalid snapshot URL: %s", url)
        return None

    import httpx
    capture_dir.mkdir(parents=True, exist_ok=True)
    out_path = _capture_path(capture_dir, safe_url)

    user = credentials.get("user") if credentials else ""
    password = credentials.get("password", "") if credentials else ""

    try:
        async with httpx.AsyncClient(verify=False, timeout=3.0, follow_redirects=True) as client:
            resp = None
            if user:
                resp = await client.get(safe_url, auth=(user, password))
                if resp.status_code == 401:
                    resp = await client.get(safe_url, auth=httpx.DigestAuth(user, password))
            else:
                resp = await client.get(safe_url)

            if resp.status_code == 401:
                is_digest = "digest" in resp.headers.get("www-authenticate", "").lower()
                for cand_u, cand_p in [("admin", "admin"), ("admin", "12345"), ("admin", "123456"), ("root", "root")]:
                    if cand_u == user and cand_p == password:
                        continue
                    try:
                        if is_digest:
                            cand_resp = await client.get(safe_url, auth=httpx.DigestAuth(cand_u, cand_p))
                        else:
                            cand_resp = await client.get(safe_url, auth=(cand_u, cand_p))
                            if cand_resp.status_code == 401:
                                cand_resp = await client.get(safe_url, auth=httpx.DigestAuth(cand_u, cand_p))
                        if cand_resp.status_code == 200 and len(cand_resp.content or b"") >= 2048:
                            resp = cand_resp
                            if credentials is not None:
                                credentials["user"] = cand_u
                                credentials["password"] = cand_p
                            break
                    except Exception:
                        continue
            content = resp.content or b""
            # Must be a real image with at least 2 KB of data and resolution >= 160x120
            is_valid_image = (
                resp.status_code == 200
                and len(content) >= 2048
                and (
                    content[:2] == b"\xff\xd8"  # JPEG SOI
                    or content[:4] == b"\x89PNG" # PNG
                    or content[:3] == b"GIF"     # GIF
                    or (content[:4] == b"RIFF" and content[8:12] == b"WEBP") # WebP
                )
            )
            if is_valid_image:
                try:
                    from PIL import Image
                    import io
                    im = Image.open(io.BytesIO(content))
                    im.load()
                    if im.width < 160 or im.height < 120:
                        is_valid_image = False
                except Exception:
                    is_valid_image = False

            if is_valid_image:
                out_path.write_bytes(content)
                return str(out_path)
    except Exception as exc:
        logger.debug("[v2 Stage3] Snapshot download failed for %s: %s", url, exc)
    return None




async def verify_single_stream(
    stream: StreamInfo,
    capture_dir: Path,
    credentials: Optional[dict] = None,
) -> bool:
    """Verify and capture a single stream (HTTP snapshot or ffmpeg frame)."""
    stream.verified = False
    stream.screenshot_path = ""
    stream.codec, stream.width, stream.height, stream.resolution = "", 0, 0, ""
    stream.transport = ""
    stream.verification_status = "failed"
    try:
        if stream.stream_type == "http_snapshot":
            path = await _download_http_snapshot(stream.url, capture_dir, credentials)
            if path:
                stream.screenshot_path = path
                stream.verified = True
                stream.transport = "http"
                try:
                    from PIL import Image
                    with Image.open(path) as frame:
                        stream.width, stream.height = frame.size
                        stream.codec = frame.format or ""
                        stream.resolution = f"{stream.width}x{stream.height}"
                except OSError:
                    pass
        elif stream.stream_type in {"rtsp", "rtsps", "rtmp", "hls", "mjpeg", "udp_rtp"}:
            c_res = await capture_stream_frame(
                stream.url, "rtsp" if stream.stream_type == "rtsps" else stream.stream_type,
                capture_dir, credentials,
            )
            if len(c_res) >= 6:
                ok, path, codec, w, h, transport = c_res[:6]
            else:
                ok, path, codec, w, h = c_res[:5]
                transport = ""
            if ok:
                stream.verified = True
                stream.screenshot_path = path
                stream.codec, stream.width, stream.height = codec, w, h
                stream.resolution = f"{w}x{h}" if w and h else ""
                stream.transport = transport
        else:
            stream.verification_status = "unsupported"

        if stream.verified:
            stream.verification_status = "verified"
            stream.auth_required = False
            return True
    except asyncio.CancelledError:
        stream.verification_status = "pending"
        raise
    except Exception as exc:
        logger.debug("[v2 Stage3] Stream verification failed for %s: %s", stream.url, exc)
    return False


async def verify_camera_streams(
    camera: CameraResult,
    capture_dir: Path,
    max_streams_to_try: Optional[int] = None,
    *,
    is_cancelled=None,
    on_stream=None,
) -> int:
    """Capture every distinct stream, including streams already marked verified.

    The optional explicit limit is retained for callers requesting a sample;
    normal scans have no per-camera cap. Timeouts apply to individual attempts.
    """
    streams = camera.streams
    if max_streams_to_try is not None:
        streams = streams[:max(0, max_streams_to_try)]
    seen = set()
    for stream in streams:
        if is_cancelled and is_cancelled():
            break
        if not stream.url or stream.url in seen:
            continue
        seen.add(stream.url)
        credentials = stream.credentials if stream.credentials is not None else camera.credentials
        await verify_single_stream(stream, capture_dir, credentials)
        if on_stream:
            on_stream(stream)

    camera.streams.sort(key=lambda s: (s.verified, bool(s.screenshot_path), s.width * s.height), reverse=True)
    return sum(s.verified for s in camera.streams)
