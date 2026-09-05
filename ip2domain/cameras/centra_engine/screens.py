import asyncio
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Optional

import aiohttp
from fastapi import HTTPException

from ip2domain.web.routers.common import (
    storage,
    camera_providers,
    CENTRA_CAPTURE_DIR,
    CAMERA_CAPTURE_DIR,
    CENTRA_CAPTURE_LOCKS,
    CENTRA_CAPTURE_LAST_CLEANUP,
    CENTRA_PREVIEW_SEMAPHORE,
    CENTRA_FFMPEG_SEMAPHORE,
    CENTRA_PERSON_FFMPEG_SEMAPHORE,
    CAMERA_CAPTURE_LOCKS,
)

logger = logging.getLogger(__name__)


def _cleanup_centra_captures(now: Optional[float] = None) -> int:
    import ip2domain.web.routers.common as common_mod
    now = now or time.time()
    if now - common_mod.CENTRA_CAPTURE_LAST_CLEANUP < 300:
        return 0
    common_mod.CENTRA_CAPTURE_LAST_CLEANUP = now
    retention = max(300, min(7 * 86400, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_RETENTION", "21600"))))
    max_files = max(100, min(20000, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_MAX_FILES", "2000"))))
    files = []
    for path in CENTRA_CAPTURE_DIR.glob("*.jpg"):
        try:
            mtime = path.stat().st_mtime
            if now - mtime > retention:
                path.unlink()
            else:
                files.append((mtime, path))
        except OSError:
            continue
    removed = 0
    for _, path in sorted(files)[:max(0, len(files) - max_files)]:
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    for path in CENTRA_CAPTURE_DIR.glob("*.tmp.jpg"):
        try:
            if now - path.stat().st_mtime > 300:
                path.unlink()
        except OSError:
            pass
    return removed


def _centra_capture_is_stale(path: Path, ttl: int) -> bool:
    try:
        return not path.is_file() or time.time() - path.stat().st_mtime >= ttl
    except OSError:
        return True


async def _generate_centra_screenshot(camera_id: str, camera: dict, path: Path,
                                      ffmpeg: Optional[str],
                                      ffmpeg_semaphore: Optional[asyncio.Semaphore] = None) -> None:
    safe_camera_id = os.path.basename(re.sub(r"[^a-zA-Z0-9_\-]", "", camera_id))
    if not safe_camera_id:
        raise HTTPException(status_code=400, detail="Некорректная камера Centra")

    base_dir = CENTRA_CAPTURE_DIR.resolve()
    safe_file_name = os.path.basename(f"{safe_camera_id}.jpg")
    safe_tmp_name = os.path.basename(f"{safe_camera_id}.tmp.jpg")
    resolved_path = (base_dir / safe_file_name).resolve()
    temporary = (base_dir / safe_tmp_name).resolve()
    if not resolved_path.is_relative_to(base_dir) or not temporary.is_relative_to(base_dir):
        raise HTTPException(status_code=400, detail="Недопустимый путь к файлу")
    path = resolved_path

    lock = CENTRA_CAPTURE_LOCKS.setdefault(safe_camera_id, asyncio.Lock())
    async with lock:
        provider = camera_providers.require("centra")
        try:
            normalized = provider.normalize(camera)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Некорректная камера Centra") from exc
        preview_sources = list(provider.snapshot_candidates(normalized))
        sources = list(provider.stream_candidates(normalized))
        if not preview_sources or any(not provider.validate_url(url) for url in preview_sources + sources):
            raise HTTPException(status_code=400, detail="Некорректный сервер камеры")
        errors = []
        preview_url = preview_sources[0]
        try:
            timeout = aiohttp.ClientTimeout(total=12, connect=4, sock_read=8)
            async with CENTRA_PREVIEW_SEMAPHORE:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(preview_url, allow_redirects=False) as response:
                        content_length = int(response.headers.get("Content-Length", "0") or 0)
                        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                        if response.status == 200 and content_type == "image/jpeg" and content_length <= 5_000_000:
                            image = await response.read()
                            if 100 <= len(image) <= 5_000_000 and image.startswith(b"\xff\xd8"):
                                temporary.write_bytes(image)
                                os.replace(temporary, path)
                                return
                        errors.append(f"{preview_url}: HTTP {response.status} {content_type}")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            errors.append(f"{preview_url}: {exc}")
        if not ffmpeg:
            logger.info("Centra screenshot %s failed: %s", camera_id, " | ".join(errors))
            raise HTTPException(status_code=503, detail="Preview недоступен, резервный FFmpeg не установлен")
        for source in sources:
            temporary.unlink(missing_ok=True)
            async with (ffmpeg_semaphore or CENTRA_FFMPEG_SEMAPHORE):
                process = await asyncio.create_subprocess_exec(
                    ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                    "-rw_timeout", "8000000", "-i", source, "-frames:v", "1",
                    "-vf", "scale=min(640\\,iw):-2", "-q:v", "5", "-update", "1", str(temporary),
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    _, error = await asyncio.wait_for(process.communicate(), timeout=12)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.communicate()
                    errors.append(f"{source}: timeout")
                    continue
            if process.returncode == 0 and temporary.is_file():
                break
            errors.append(f'{source}: {error.decode(errors="replace")[-300:]}')
        if not temporary.is_file():
            logger.info("Centra screenshot %s failed: %s", camera_id, " | ".join(errors))
            raise HTTPException(status_code=502, detail="Не удалось получить свежий кадр")
        os.replace(temporary, path)


async def _refresh_centra_screenshot(camera_id: str, camera: dict, path: Path,
                                     ffmpeg: Optional[str]) -> None:
    try:
        await _generate_centra_screenshot(camera_id, camera, path, ffmpeg)
    except Exception as exc:
        logger.info("Centra background screenshot refresh %s failed: %s", camera_id, exc)


async def _prepare_centra_person_frame(camera_id: str, screenshot_ttl: int,
                                       ffmpeg: Optional[str]) -> tuple:
    import sys
    app_mod = sys.modules.get("ip2domain.web.app")
    _storage = getattr(app_mod, "storage", storage)
    _capture_dir = getattr(app_mod, "CENTRA_CAPTURE_DIR", CENTRA_CAPTURE_DIR)
    _generate_fn = getattr(app_mod, "_generate_centra_screenshot", _generate_centra_screenshot)
    _ffmpeg_sem = getattr(app_mod, "CENTRA_PERSON_FFMPEG_SEMAPHORE", CENTRA_PERSON_FFMPEG_SEMAPHORE)

    safe_camera_id = re.sub(r"[^a-zA-Z0-9_\-]", "", camera_id)
    if not safe_camera_id or safe_camera_id != camera_id:
        return camera_id, None, None, "Камера отсутствует в базе"
    camera = _storage.get_centra_camera(safe_camera_id)
    if not camera:
        return safe_camera_id, None, None, "Камера отсутствует в базе"
    path = (_capture_dir / f"{safe_camera_id}.jpg").resolve()
    if not path.is_relative_to(_capture_dir.resolve()):
        return safe_camera_id, None, None, "Недопустимый путь к файлу"
    try:
        if _centra_capture_is_stale(path, screenshot_ttl):
            await _generate_fn(safe_camera_id, camera, path, ffmpeg, _ffmpeg_sem)
        return safe_camera_id, camera, path, None
    except Exception as exc:
        return safe_camera_id, camera, path, str(exc)


async def _generate_generic_ip_screenshot(camera: dict, path: Path) -> None:
    provider = camera_providers.require("generic-ip")
    try:
        normalized = provider.normalize(camera)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    key = str(camera.get("uid") or normalized.external_id)
    safe_key = re.sub(r"[^a-zA-Z0-9_\-]", "", key) or "default"
    lock = CAMERA_CAPTURE_LOCKS.setdefault(safe_key, asyncio.Lock())
    async with lock:
        resolved_path = path.resolve()
        temporary = resolved_path.with_suffix(".tmp.jpg")
        errors = []
        for endpoint in normalized.endpoints:
            if endpoint.kind == "snapshot":
                try:
                    timeout = aiohttp.ClientTimeout(total=12, connect=4, sock_read=8)
                    async with CAMERA_PREVIEW_SEMAPHORE:
                        async with aiohttp.ClientSession(timeout=timeout) as session:
                            async with session.get(endpoint.url, allow_redirects=True) as response:
                                content_length = int(response.headers.get("Content-Length", "0") or 0)
                                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                                if response.status == 200 and content_type == "image/jpeg" and content_length <= 5_000_000:
                                    image = await response.read()
                                    if 100 <= len(image) <= 5_000_000 and image.startswith(b"\xff\xd8"):
                                        temporary.write_bytes(image)
                                        os.replace(temporary, path)
                                        return
                                errors.append(f"{endpoint.url}: HTTP {response.status} {content_type}")
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    errors.append(str(exc))
            elif endpoint.kind in {"hls", "rtsp"}:
                ffmpeg = shutil.which("ffmpeg")
                if not ffmpeg:
                    errors.append("FFmpeg is not installed")
                    continue
                temporary.unlink(missing_ok=True)
                input_options = (["-rtsp_transport", "tcp", "-timeout", "8000000"]
                                 if endpoint.kind == "rtsp" else ["-rw_timeout", "8000000"])
                async with CENTRA_FFMPEG_SEMAPHORE:
                    process = await asyncio.create_subprocess_exec(
                        ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                        *input_options, "-i", endpoint.url, "-frames:v", "1",
                        "-vf", "scale=min(640\\,iw):-2", "-q:v", "5", "-update", "1", str(temporary),
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
                    try:
                        _, error = await asyncio.wait_for(process.communicate(), timeout=12)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.communicate()
                        errors.append("FFmpeg timeout")
                        continue
                if process.returncode == 0 and temporary.is_file():
                    os.replace(temporary, path)
                    return
                errors.append(error.decode(errors="replace")[-300:])
        raise HTTPException(status_code=502, detail="Не удалось получить кадр: " + " | ".join(errors[-3:]))
