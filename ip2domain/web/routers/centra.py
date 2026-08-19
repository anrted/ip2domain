"""Centra Gateway, Yandex Map geocoding, Screenshots and ONNX YOLO Person Detection."""
import asyncio
import json
import logging
import os
import re
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional
from urllib.parse import urlparse
import aiohttp
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ip2domain.core.target_policy import validate_network_target
from ip2domain.web.routers.common import (
    storage,
    camera_providers,
    CENTRA_JOBS,
    CENTRA_PERSON_JOBS,
    CENTRA_CAPTURE_DIR,
    CENTRA_CAPTURE_LOCKS,
    CENTRA_CAPTURE_REFRESH_TASKS,
    CENTRA_CAPTURE_LAST_CLEANUP,
    CENTRA_PREVIEW_SEMAPHORE,
    CENTRA_FFMPEG_SEMAPHORE,
    CENTRA_PERSON_FFMPEG_SEMAPHORE,
    CENTRA_PERSON_MODEL,
    CAMERA_SNAPSHOT_CACHE,
    CAMERA_CAPTURE_LOCKS,
    CAMERA_PREVIEW_SEMAPHORE,
    REMOTE_CAPTURE_DIR,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["centra"])

class CentraDiscoveryRequest(BaseModel):
    camera_type: str = Field(default="I", min_length=1, max_length=100)
    base_url: Optional[str] = Field(default=None, max_length=253)
    pin_color: Literal["violet", "blue", "red", "green", "orange", "yellow", "pink", "gray"] = "violet"
    start_id: int = Field(default=1, ge=1, le=1000000)
    end_id: int = Field(default=40000, ge=1, le=1000000)
    entrance_start: int = Field(default=1, ge=1, le=100)
    entrance_end: int = Field(default=5, ge=1, le=100)
    concurrency: int = Field(default=20, ge=1, le=50)
    skip_existing: bool = False

class CentraCoordinatesRequest(BaseModel):
    address: str = Field(min_length=1, max_length=500)
    coordinates: List[float] = Field(min_items=2, max_items=2)

class CentraPersonDetectionRequest(BaseModel):
    camera_ids: List[str] = Field(default_factory=list, max_items=100)
    all_cameras: bool = False
    camera_type: str = Field(default="", max_length=1)
    confidence: float = Field(default=0.45, ge=0.2, le=0.9)

class CentraGeocodeRequest(BaseModel):
    address: str = Field(min_length=1, max_length=500)

DEFAULT_CENTRA_CAMERAS = [{
    "id": "I-374-1",
    "camera_type": "I",
    "title": "Домофон Сибиряков-Гвардейцев 14",
    "address": "Новокузнецк, ул. Сибиряков-Гвардейцев, 14",
    "embed_url": "https://flus4.mycentra.ru/I-374-1/embed.html",
    "media_info_url": "https://flus4.mycentra.ru/I-374-1/media_info.json",
}]

def _cleanup_centra_captures(now: Optional[float] = None) -> int:
    global CENTRA_CAPTURE_LAST_CLEANUP
    now = now or time.time()
    if now - CENTRA_CAPTURE_LAST_CLEANUP < 300:
        return 0
    CENTRA_CAPTURE_LAST_CLEANUP = now
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

def _centra_cameras() -> List[dict]:
    raw = os.environ.get("IP2DOMAIN_CENTRA_CAMERAS")
    if not raw:
        return DEFAULT_CENTRA_CAMERAS
    try:
        cameras = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Ignoring invalid IP2DOMAIN_CENTRA_CAMERAS: %s", exc)
        return DEFAULT_CENTRA_CAMERAS
    if not isinstance(cameras, list):
        logger.warning("Ignoring IP2DOMAIN_CENTRA_CAMERAS: expected a JSON array")
        return DEFAULT_CENTRA_CAMERAS
    return cameras

def _centra_address(title: str) -> str:
    address = re.sub(r"^домофон\s+", "", str(title), flags=re.IGNORECASE).strip()
    configured_city = os.environ.get("IP2DOMAIN_CENTRA_CITY", "Новокузнецк").strip()
    configured_region = os.environ.get("IP2DOMAIN_CENTRA_REGION", "Кемеровская область").strip()
    city_match = re.search(r"\(([^()]*)\)\s*$", address)
    city = city_match.group(1).strip() if city_match else configured_city
    if city_match:
        address = address[:city_match.start()].strip()
    nested_locality = re.fullmatch(
        r"(?i)(Таштагол|Шерегеш),\s*(?:ул\.?\s+)?(.+?),\s*(\d+[а-я]?(?:/\d+)?)",
        address,
    )
    if nested_locality:
        city = nested_locality.group(1).title()
        street = nested_locality.group(2).strip().title()
        address = f"ул. {street}, {nested_locality.group(3)}"
    else:
        street_match = re.fullmatch(r"(.+?)\s+(\d+[А-Яа-яA-Za-z]?(?:/\d+)?)", address)
        if street_match:
            street, house = street_match.groups()
            address = f"ул. {street.strip()}, {house}"
    location = ", ".join(part for part in ("Россия", configured_region, city) if part)
    result = f"{location}, {address}" if location and address else address
    return _centra_address_override(result)

def _centra_address_override(address: str) -> str:
    nested_locality = re.fullmatch(
        r"(?i)(Россия,\s*Кемеровская область(?:\s*-\s*Кузбасс)?,\s*)"
        r"Новокузнецк,\s*(?:ул\.?\s+)?(Таштагол|Шерегеш),\s*"
        r"(?:ул\.?\s+)?(.+?),\s*(\d+[а-я]?(?:/\d+)?)",
        address.strip(),
    )
    if nested_locality:
        return (f"{nested_locality.group(1)}{nested_locality.group(2).title()}, "
                f"ул. {nested_locality.group(3)}, {nested_locality.group(4)}")
    overrides = {
        ("нестерова", "26а"): "Осинники",
        ("50 лет октября", "31"): "Осинники",
    }
    normalized = address.casefold().replace("ё", "е")
    for (street, house), locality in overrides.items():
        if re.search(rf"(?i),\s*(?:ул\.?\s+)?{re.escape(street)}\s*,\s*{re.escape(house)}\s*$", normalized):
            parts = [part.strip() for part in address.split(",")]
            if len(parts) >= 3:
                parts[2] = locality
                return ", ".join(parts)
    return address

def _dadata_address(address: str) -> str:
    return re.sub(
        r"(?i)(?<=,\s)(?:ул(?:ица)?|пр-?т|просп(?:ект)?|пр-?д|проезд|пер(?:еулок)?)\.?\s+",
        "",
        address.strip(),
    )

def _centra_locality(address: str) -> str:
    parts = [part.strip() for part in address.split(",") if part.strip()]
    return parts[2] if len(parts) >= 3 else os.environ.get("IP2DOMAIN_CENTRA_CITY", "Новокузнецк")

def _dadata_queries(address: str) -> List[str]:
    primary = _dadata_address(address)
    aliases = [primary]
    replacements = {
        r"(?i)(?<=,\s)Рихарда\s+Зорге(?=,|$)": "Зорге",
        r"(?i)(?<=,\s)(\d+)[-‐‑–—]?(?:й|ый|ой)\s+микрорайон(?=,|$)": r"Микрорайон \1",
    }
    for pattern, replacement in replacements.items():
        candidate = re.sub(pattern, replacement, primary)
        if candidate != primary and candidate not in aliases:
            aliases.append(candidate)
    return aliases

def _centra_discovery_types(value: str) -> List[str]:
    value = value.strip().upper().replace(" ", "")
    if value in {"I", "G"}:
        return [value]
    types = []
    for token in value.split(","):
        if re.fullmatch(r"[A-Z]", token):
            candidates = [token]
        elif re.fullmatch(r"[A-Z]-[A-Z]", token) and token[0] <= token[2]:
            candidates = [chr(code) for code in range(ord(token[0]), ord(token[2]) + 1)]
        else:
            raise HTTPException(status_code=400, detail="Типы: буквы через запятую или диапазон A-Z")
        for camera_type in candidates:
            if camera_type not in {"I", "G"} and camera_type not in types:
                types.append(camera_type)
    if not types:
        raise HTTPException(status_code=400, detail="В пользовательском поиске I и G использовать нельзя")
    return types

def _centra_capture_is_stale(path: Path, ttl: int) -> bool:
    try:
        return not path.is_file() or time.time() - path.stat().st_mtime >= ttl
    except OSError:
        return True

async def _generate_centra_screenshot(camera_id: str, camera: dict, path: Path,
                                      ffmpeg: Optional[str],
                                      ffmpeg_semaphore: Optional[asyncio.Semaphore] = None) -> None:
    lock = CENTRA_CAPTURE_LOCKS.setdefault(camera_id, asyncio.Lock())
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
        temporary = path.with_suffix(".tmp.jpg")
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
    camera = storage.get_centra_camera(camera_id)
    if not camera:
        return camera_id, None, None, "Камера отсутствует в базе"
    path = CENTRA_CAPTURE_DIR / f"{camera_id}.jpg"
    try:
        if _centra_capture_is_stale(path, screenshot_ttl):
            await _generate_centra_screenshot(camera_id, camera, path, ffmpeg,
                                              CENTRA_PERSON_FFMPEG_SEMAPHORE)
        return camera_id, camera, path, None
    except Exception as exc:
        return camera_id, camera, path, str(exc)

async def _generate_generic_ip_screenshot(camera: dict, path: Path) -> None:
    provider = camera_providers.require("generic-ip")
    try:
        normalized = provider.normalize(camera)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    key = str(camera.get("uid") or normalized.external_id)
    lock = CAMERA_CAPTURE_LOCKS.setdefault(key, asyncio.Lock())
    async with lock:
        temporary = path.with_suffix(".tmp.jpg")
        errors = []
        for endpoint in sorted(normalized.endpoints, key=lambda item: item.priority, reverse=True):
            parsed = urlparse(endpoint.url)
            allowed, _ = await validate_network_target(parsed.hostname or "")
            if not allowed:
                errors.append(f"{endpoint.kind}: target policy denied {parsed.hostname}")
                continue
            if endpoint.kind == "snapshot":
                try:
                    timeout = aiohttp.ClientTimeout(total=12, connect=4, sock_read=8)
                    async with CAMERA_PREVIEW_SEMAPHORE:
                        async with aiohttp.ClientSession(timeout=timeout) as session:
                            async with session.get(endpoint.url, allow_redirects=False) as response:
                                image = await response.read() if response.status == 200 else b""
                                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                                if content_type == "image/jpeg" and 100 <= len(image) <= 5_000_000 and image.startswith(b"\xff\xd8"):
                                    temporary.write_bytes(image)
                                    os.replace(temporary, path)
                                    return
                                errors.append(f"snapshot HTTP {response.status} {content_type}")
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

async def _run_centra_discovery(job_id: str, req: CentraDiscoveryRequest):
    possible_total = (req.end_id - req.start_id + 1) * (req.entrance_end - req.entrance_start + 1)
    checked = found = retries = 0
    current_building = req.start_id
    semaphore = asyncio.Semaphore(req.concurrency)
    timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_read=5)
    headers = {"User-Agent": "ip2domain-centra-discovery/1.0"}
    known = {camera["id"]: camera for camera in storage.get_centra_cameras()}
    camera_type = req.camera_type.upper()
    numbered_hosts = ["flus4.mycentra.ru", "flus3.mycentra.ru", "flus2.mycentra.ru",
                      "flus1.mycentra.ru", "flus5.mycentra.ru", "flus6.mycentra.ru"]
    automatic_hosts = {
        "I": numbered_hosts + ["flus.mycentra.ru"],
        "G": ["flus.mycentra.ru"] + numbered_hosts,
    }
    hosts = ([urlparse(req.base_url).hostname] if req.base_url else
             automatic_hosts.get(camera_type, ["flus.mycentra.ru"] + numbered_hosts))
    previously_checked = set(storage.get_centra_checked_ids(
        camera_type, req.start_id, req.end_id, req.entrance_start, req.entrance_end
    )) if req.skip_existing else set()
    previously_checked.update(camera_id for camera_id in known if req.skip_existing and
        (match := re.fullmatch(rf"{camera_type}-(\d+)-(\d+)", camera_id, re.IGNORECASE)) and
        req.start_id <= int(match.group(1)) <= req.end_id and
        req.entrance_start <= int(match.group(2)) <= req.entrance_end)
    skipped = len(previously_checked)
    total = possible_total - skipped
    check_batch = []
    started_at = time.time()

    def cancellation_requested() -> bool:
        job = CENTRA_JOBS.get(job_id) or {}
        return job.get("status") == "cancelling" or bool(job.get("cancel_requested"))

    async def probe(session: aiohttp.ClientSession, building: int, entrance: int):
        nonlocal checked, found, retries, current_building
        camera_id = f"{camera_type}-{building}-{entrance}"
        available = False
        conclusive = not bool(req.base_url)
        try:
            data = None
            selected_host = None
            media_url = None
            camera_hosts = list(hosts)
            existing = known.get(camera_id) or {}
            saved_host = str(existing.get("stream_host") or "").strip().lower()
            if not saved_host:
                saved_host = (urlparse(str(existing.get("embed_url") or "")).hostname or "").lower()
            if saved_host in camera_hosts:
                camera_hosts.remove(saved_host)
                camera_hosts.insert(0, saved_host)
            for host in camera_hosts:
                if cancellation_requested():
                    conclusive = False
                    return
                candidate_url = f"https://{host}/{camera_id}/media_info.json"
                for attempt in range(2):
                    if cancellation_requested():
                        conclusive = False
                        return
                    try:
                        async with semaphore:
                            async with session.get(candidate_url, allow_redirects=False) as response:
                                if response.status == 404:
                                    break
                                if response.status != 200:
                                    conclusive = False
                                    break
                                candidate = await response.json(content_type=None)
                        if isinstance(candidate, dict) and candidate.get("tracks"):
                            data, selected_host, media_url = candidate, host, candidate_url
                        break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt == 0:
                            retries += 1
                            await asyncio.sleep(0.35)
                            continue
                        conclusive = False
                    except (ValueError, TypeError):
                        conclusive = False
                        break
                if data and selected_host:
                    break
            if not data or not selected_host:
                return
            video = next((track for track in data["tracks"] if track.get("content") == "video"), {})
            title = str(data.get("title") or camera_id).strip()
            address = _centra_address(title)
            camera = {
                "id": camera_id,
                "camera_type": camera_type,
                "pin_color": req.pin_color,
                "building_id": building,
                "entrance": entrance,
                "title": title,
                "address": address,
                "stream_host": selected_host,
                "embed_url": f"https://{selected_host}/{camera_id}/embed.html",
                "media_info_url": media_url,
                "available": True,
                "video": {key: video.get(key) for key in ("codec", "width", "height", "fps", "avg_fps") if video.get(key) is not None},
            }
            storage.save_centra_cameras([camera])
            available = True
            found += 1
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            pass
        finally:
            if not available and conclusive and camera_id in known:
                storage.save_centra_cameras([{**known[camera_id], "available": False}])
            checked += 1
            if available or conclusive:
                check_batch.append({"camera_id": camera_id, "camera_type": camera_type,
                                    "building_id": building, "entrance": entrance,
                                    "found": available})
                if len(check_batch) >= 250:
                    storage.save_centra_scan_checks(check_batch[:])
                    check_batch.clear()
            current_building = max(current_building, building)
            if checked == total or checked % max(25, req.concurrency) == 0:
                pct = min(99, int(checked * 100 / total))
                elapsed = max(0.001, time.time() - started_at)
                speed = checked / elapsed
                eta_seconds = max(0, int((total - checked) / speed)) if speed else None
                CENTRA_JOBS.update(job_id, status="running", progress_pct=pct,
                    stage=(f"Тип {camera_type} · дом {current_building:,} из {req.end_id:,} · "
                           f"проверено камер {checked:,} из {total:,} · найдено {found}"),
                    checked=checked, found=found, current_building=current_building,
                    retries=retries, started_at=started_at, speed=round(speed, 2), eta_seconds=eta_seconds)

    try:
        CENTRA_JOBS.update(job_id, status="running", progress_pct=0, started_at=started_at,
                           speed=0, eta_seconds=None,
                           stage=(f"Подготовка типа {camera_type} · {total:,} проверок"
                                  + (f" · пропущено {skipped:,}" if skipped else "")))
        if total == 0:
            CENTRA_JOBS.update(job_id, status="completed", progress_pct=100,
                               stage=f"Готово · все {skipped:,} камер уже находятся в базе",
                               checked=0, found=0, skipped=skipped)
            return
        connector = aiohttp.TCPConnector(limit=req.concurrency, ttl_dns_cache=300)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
            pending = set()
            cancelled = False
            for building in range(req.start_id, req.end_id + 1):
                for entrance in range(req.entrance_start, req.entrance_end + 1):
                    if cancellation_requested():
                        cancelled = True
                        break
                    if req.skip_existing and f"{camera_type}-{building}-{entrance}" in previously_checked:
                        continue
                    pending.add(asyncio.create_task(probe(session, building, entrance)))
                    if len(pending) >= req.concurrency * 4:
                        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                        for task in done:
                            await task
                if cancelled:
                    break
            if pending:
                if cancelled or cancellation_requested():
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    cancelled = True
                else:
                    await asyncio.gather(*pending)
        storage.save_centra_scan_checks(check_batch)
        if cancelled or cancellation_requested():
            CENTRA_JOBS.update(job_id, status="cancelled", progress_pct=min(99, int(checked * 100 / max(1, total))),
                               stage=f"Остановлено · проверено {checked:,} · найдено {found} · пропущено {skipped:,}",
                               checked=checked, found=found, skipped=skipped, cancel_requested=True)
            return
        CENTRA_JOBS.update(job_id, status="completed", progress_pct=100,
                           stage=(f"Готово · тип {camera_type} · дома {req.start_id:,}–{req.end_id:,} · "
                                  f"проверено камер {checked:,} · найдено {found}"
                                  + (f" · пропущено {skipped:,}" if skipped else "")),
                           checked=checked, found=found, skipped=skipped, current_building=req.end_id,
                           speed=round(checked / max(.001, time.time() - started_at), 2), eta_seconds=0)
    except Exception as exc:
        logger.error("Centra discovery %s failed: %s", job_id, exc, exc_info=True)
        CENTRA_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")

@router.get("/api/cameras/centra")
def get_centra_cameras():
    stored = storage.get_centra_cameras()
    cameras = ([camera for camera in stored if camera.get("available", True)]
               if stored else _centra_cameras())
    for camera in cameras:
        camera["address"] = _centra_address(camera.get("title") or camera.get("address", ""))
        embed_url = str(camera.get("embed_url") or "")
        if "/embed.html" in embed_url:
            camera["embed_url"] = embed_url.split("?", 1)[0]
    cached = storage.get_centra_coordinates([camera.get("address", "") for camera in cameras])
    for camera in cameras:
        if camera.get("address") in cached:
            camera["coordinates"] = cached[camera["address"]]
    def camera_order(camera):
        match = re.fullmatch(r"([A-Z])-(\d+)-(\d+)", str(camera.get("id", "")), re.IGNORECASE)
        return (int(match.group(2)), int(match.group(3)), match.group(1).upper()) if match else (10**9, 10**9, "Z")
    cameras.sort(key=camera_order)
    used_pin_colors = {"red": "I", "blue": "G", "green": "H/P"}
    type_pin_colors = {"I": "red", "G": "blue", "H": "green", "P": "green"}
    for camera in (stored or cameras):
        camera_type = str(camera.get("camera_type") or camera.get("id", "")).split("-", 1)[0].upper()
        color = type_pin_colors.get(camera_type) or str(camera.get("pin_color") or "violet")
        if camera_type and color:
            used_pin_colors.setdefault(color, camera_type)
            type_pin_colors[camera_type] = color
    for camera in cameras:
        camera_type = str(camera.get("camera_type") or camera.get("id", "")).split("-", 1)[0].upper()
        camera["pin_color"] = type_pin_colors.get(camera_type) or str(camera.get("pin_color") or "violet")
    return {
        "cameras": cameras,
        "used_pin_colors": used_pin_colors,
        "type_pin_colors": type_pin_colors,
        "yandex_maps_api_key": os.environ.get("YANDEX_MAPS_API_KEY", ""),
        "geocode_batch_limit": max(0, min(100, int(os.environ.get("IP2DOMAIN_GEOCODE_BATCH_LIMIT", "25")))),
    }

@router.put("/api/cameras/centra/coordinates")
def save_centra_coordinates(req: CentraCoordinatesRequest):
    latitude, longitude = req.coordinates
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise HTTPException(status_code=400, detail="Некорректные координаты")
    storage.save_centra_coordinates(req.address, req.coordinates)
    return {"status": "saved"}

@router.post("/api/cameras/centra/geocode")
async def geocode_centra_address(req: CentraGeocodeRequest):
    cached = storage.get_centra_coordinates([req.address]).get(req.address)
    if cached:
        return {"coordinates": cached, "provider": "cache"}
    token = os.environ.get("DADATA_API_KEY", "").strip()
    if not token:
        raise HTTPException(status_code=503, detail="Резервный геокодер DaData не настроен")
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json",
               "User-Agent": "ip2domain-centra-geocoder/1.0"}
    expected_locality = _centra_locality(req.address)
    expected_city = expected_locality.casefold()
    try:
        timeout = aiohttp.ClientTimeout(total=10, connect=4, sock_read=6)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for query in _dadata_queries(req.address):
                async with session.post("https://suggestions.dadata.ru/suggestions/api/4_1/rs/suggest/address",
                                        json={"query": query, "count": 5}) as response:
                    if response.status != 200:
                        raise HTTPException(status_code=502, detail=f"DaData вернула HTTP {response.status}")
                    data = await response.json()
                for suggestion in data.get("suggestions", []):
                    item = suggestion.get("data") or {}
                    localities = " ".join(str(item.get(key) or "") for key in
                                          ("city", "settlement", "area", "region_with_type")).casefold()
                    latitude, longitude = item.get("geo_lat"), item.get("geo_lon")
                    if expected_city in localities and latitude is not None and longitude is not None:
                        coordinates = [float(latitude), float(longitude)]
                        storage.save_centra_coordinates(req.address, coordinates)
                        return {"coordinates": coordinates, "provider": "dadata"}
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=502, detail="DaData временно недоступна") from exc
    raise HTTPException(status_code=404, detail=f"DaData не нашла точные координаты в {expected_locality}")

@router.post("/api/cameras/centra/discover")
async def start_centra_discovery(req: CentraDiscoveryRequest, background_tasks: BackgroundTasks):
    camera_types = _centra_discovery_types(req.camera_type)
    if req.base_url:
        parsed = urlparse(req.base_url)
        hostname = (parsed.hostname or "").lower()
        if (parsed.scheme != "https" or not re.fullmatch(r"[a-z0-9-]+\.mycentra\.ru", hostname)
                or parsed.port is not None or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise HTTPException(status_code=400, detail=(
                "Сервер должен быть полным HTTPS URL без пути, например https://flus6.mycentra.ru"
            ))
    type_colors = {"I": "red", "G": "blue", "H": "green", "P": "green"}
    saved_cameras = storage.get_centra_cameras()
    saved_types = set()
    for camera in saved_cameras:
        stored_type = str(camera.get("camera_type") or camera.get("id", "")).split("-", 1)[0].upper()
        stored_color = type_colors.get(stored_type) or str(camera.get("pin_color") or "violet")
        if stored_type and stored_color:
            saved_types.add(stored_type)
            type_colors[stored_type] = stored_color
    excluded_types = []
    if req.skip_existing and len(camera_types) > 1:
        excluded_types = [camera_type for camera_type in camera_types if camera_type in saved_types]
        camera_types = [camera_type for camera_type in camera_types if camera_type not in saved_types]
        if not camera_types:
            raise HTTPException(status_code=400, detail="Все выбранные типы уже имеют найденные камеры в базе")
    color_owners = {camera_type for camera_type, color in type_colors.items() if color == req.pin_color}
    new_types = [camera_type for camera_type in camera_types if camera_type not in type_colors]
    if new_types and color_owners:
        owners = ", ".join(sorted(color_owners))
        raise HTTPException(status_code=400,
                            detail=f"Цвет уже используется типами {owners}. Выберите свободный цвет")
    if req.end_id < req.start_id:
        raise HTTPException(status_code=400, detail="Конечный ID должен быть не меньше начального")
    if req.entrance_end < req.entrance_start:
        raise HTTPException(status_code=400, detail="Конечный подъезд должен быть не меньше начального")
    possible_per_type = (req.end_id - req.start_id + 1) * (req.entrance_end - req.entrance_start + 1)
    totals = []
    for camera_type in camera_types:
        known_ids = set(storage.get_centra_checked_ids(
            camera_type, req.start_id, req.end_id, req.entrance_start, req.entrance_end
        )) if req.skip_existing else set()
        if req.skip_existing:
            known_ids.update(camera.get("id") for camera in saved_cameras)
        skipped = sum(1 for camera_id in known_ids if camera_id and
            (match := re.fullmatch(rf"{camera_type}-(\d+)-(\d+)", camera_id, re.IGNORECASE)) and
            req.start_id <= int(match.group(1)) <= req.end_id and
            req.entrance_start <= int(match.group(2)) <= req.entrance_end)
        totals.append((camera_type, possible_per_type - skipped, skipped))
    total = sum(item[1] for item in totals)
    scan_limit = max(1, min(2000000, int(os.environ.get("IP2DOMAIN_CENTRA_SCAN_LIMIT", "500000"))))
    if total > scan_limit:
        raise HTTPException(status_code=400,
                            detail=f"За один запуск можно проверить не более {scan_limit:,} камер")
    active_jobs = storage.list_jobs("centra_discovery", ["queued", "running", "cancelling"])
    requested_host = (urlparse(req.base_url).hostname or "").lower() if req.base_url else ""
    duplicates = []
    for camera_type, _, _ in totals:
        duplicate = next((job for job in active_jobs
            if str(job.get("target") or "").startswith(f"{camera_type}-")
            and job.get("start_id") == req.start_id and job.get("end_id") == req.end_id
            and job.get("entrance_start") == req.entrance_start and job.get("entrance_end") == req.entrance_end
            and bool(job.get("skip_existing")) == req.skip_existing
            and str(job.get("base_host") or "") == requested_host
            and str(job.get("pin_color") or "") == type_colors.get(camera_type, req.pin_color)), None)
        if duplicate:
            duplicates.append(duplicate)
    if duplicates:
        job_ids = [job["job_id"] for job in duplicates]
        return {"status": "already_running", "job_id": job_ids[0], "job_ids": job_ids,
                "types": camera_types, "total": sum(int(job.get("total") or 0) for job in duplicates),
                "skipped": sum(int(job.get("skipped") or 0) for job in duplicates)}
    job_ids = []
    for camera_type, type_total, skipped in totals:
        job_id = uuid.uuid4().hex[:12]
        type_req = req.copy(update={"camera_type": camera_type, "pin_color": type_colors.get(camera_type, req.pin_color)})
        CENTRA_JOBS.create(job_id, {"job_id": job_id, "target": f"{camera_type}-{req.start_id}-{req.end_id}",
            "status": "queued", "progress_pct": 0, "stage": "В очереди", "error": "",
            "total": type_total, "checked": 0, "found": 0, "skipped": skipped,
            "base_host": requested_host,
            "pin_color": type_req.pin_color,
            "skip_existing": req.skip_existing, "start_id": req.start_id, "end_id": req.end_id,
            "entrance_start": req.entrance_start, "entrance_end": req.entrance_end})
        background_tasks.add_task(_run_centra_discovery, job_id, type_req)
        job_ids.append(job_id)
    return {"status": "queued", "job_id": job_ids[0], "job_ids": job_ids, "types": camera_types,
            "excluded_types": excluded_types, "total": total, "skipped": sum(item[2] for item in totals)}

@router.get("/api/cameras/centra/discover/active")
def get_active_centra_discoveries():
    active_statuses = {"queued", "running", "cancelling"}
    fields = ("job_id", "target", "status", "progress_pct", "stage", "total", "checked",
              "found", "skipped", "start_id", "end_id", "entrance_start", "entrance_end",
              "started_at", "speed", "eta_seconds")
    persisted = storage.list_jobs("centra_discovery", sorted(active_statuses))
    jobs = [{field: job.get(field) for field in fields} for job in persisted]
    return {"jobs": jobs}

@router.get("/api/cameras/centra/discover/{job_id}")
def get_centra_discovery(job_id: str):
    job = CENTRA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job

@router.post("/api/cameras/centra/discover/{job_id}/cancel")
def cancel_centra_discovery(job_id: str):
    job = CENTRA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    if job.get("status") not in {"queued", "running", "cancelling"}:
        return job
    CENTRA_JOBS.update(job_id, status="cancelling", cancel_requested=True,
                       stage="Остановка поиска...")
    return CENTRA_JOBS.get(job_id)

@router.delete("/api/cameras/centra")
def clear_centra_cameras():
    return {"status": "cleared", "deleted": storage.clear_centra_cameras()}

@router.get("/api/cameras/centra/screens")
def get_centra_screens(offset: int = Query(default=0, ge=0),
                       limit: int = Query(default=100, ge=1, le=100),
                       camera_type: str = Query(default="", max_length=1),
                       search: str = Query(default="", max_length=200)):
    if camera_type and not re.fullmatch(r"[A-Za-z]", camera_type):
        raise HTTPException(status_code=400, detail="Некорректный тип камеры")
    page = storage.list_centra_cameras_page(offset, limit, camera_type, search)
    ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300"))))
    now = time.time()
    for camera in page["cameras"]:
        camera["embed_url"] = str(camera.get("embed_url") or "").split("?", 1)[0]
        camera["screenshot_url"] = f'/api/cameras/centra/screens/{camera.get("id")}.jpg'
        cached = CENTRA_CAPTURE_DIR / f'{str(camera.get("id") or "").upper()}.jpg'
        try:
            camera["screenshot_stale"] = cached.is_file() and now - cached.stat().st_mtime >= ttl
        except OSError:
            camera["screenshot_stale"] = False
    page.update({"offset": offset, "limit": limit, "has_more": offset + len(page["cameras"]) < page["total"],
                 "preview_primary": True, "ffmpeg_available": shutil.which("ffmpeg") is not None})
    return page

@router.get("/api/cameras/centra/screens/{camera_id}.jpg")
async def get_centra_screenshot(camera_id: str, refresh: bool = False):
    if not re.fullmatch(r"[A-Z]-\d+-\d+", camera_id, re.IGNORECASE):
        raise HTTPException(status_code=404, detail="Камера не найдена")
    camera_id = camera_id.upper()
    camera = storage.get_centra_camera(camera_id)
    if not camera or not camera.get("available", True):
        raise HTTPException(status_code=404, detail="Камера не найдена")
    _cleanup_centra_captures()
    ffmpeg = shutil.which("ffmpeg")
    path = CENTRA_CAPTURE_DIR / f"{camera_id}.jpg"
    ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300"))))
    if refresh and camera_id in CENTRA_CAPTURE_REFRESH_TASKS:
        await CENTRA_CAPTURE_REFRESH_TASKS[camera_id]
        if path.is_file():
            return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    if refresh and path.is_file() and time.time() - path.stat().st_mtime < ttl:
        return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    if path.is_file() and not refresh:
        if time.time() - path.stat().st_mtime >= ttl and camera_id not in CENTRA_CAPTURE_REFRESH_TASKS:
            task = asyncio.create_task(_refresh_centra_screenshot(camera_id, camera, path, ffmpeg))
            CENTRA_CAPTURE_REFRESH_TASKS[camera_id] = task
            task.add_done_callback(lambda _task, key=camera_id: CENTRA_CAPTURE_REFRESH_TASKS.pop(key, None))
        return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    await _generate_centra_screenshot(camera_id, camera, path, ffmpeg)
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})

@router.get("/api/camera-catalog/{provider_id}/{external_id}/snapshot.jpg")
async def get_provider_screenshot(provider_id: str, external_id: str, refresh: bool = False):
    camera = storage.get_camera(provider_id, external_id)
    if not camera or not camera.get("available", True):
        raise HTTPException(status_code=404, detail="Камера не найдена")
    if provider_id == "centra":
        return await get_centra_screenshot(external_id, refresh)
    if provider_id != "generic-ip":
        raise HTTPException(status_code=501, detail="Провайдер не поддерживает снимки")
    path = CAMERA_SNAPSHOT_CACHE.path(provider_id, external_id)
    ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CAMERA_SCREEN_TTL", "300"))))
    if refresh or _centra_capture_is_stale(path, ttl):
        await _generate_generic_ip_screenshot(camera, path)
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})

async def _run_centra_person_detection(job_id: str, camera_ids: List[str], confidence: float) -> None:
    from ip2domain.core.person_detector import detect_people
    from ip2domain.core.person_reid import assign_identities_stateless
    job = CENTRA_PERSON_JOBS[job_id]
    started_at = time.time()
    batch_size = 100
    batch_pause = max(0.0, min(30.0, float(os.environ.get("IP2DOMAIN_CENTRA_PEOPLE_BATCH_PAUSE", "2"))))
    prefetch = max(1, min(12, int(os.environ.get("IP2DOMAIN_CENTRA_PEOPLE_PREFETCH", "6"))))
    screenshot_ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300"))))
    job.update(status="running", stage="Подготовка модели", started_at=started_at)
    ffmpeg = shutil.which("ffmpeg")

    def record_failure(camera_id: str, reason: str) -> None:
        message = str(reason or "Неизвестная ошибка").strip()[:300]
        job["failed"] += 1
        job["failure_details"].append({"camera_id": camera_id, "error": message})
        del job["failure_details"][:-100]
        logger.warning("Centra person analysis failed for %s: %s", camera_id, message)

    tasks = {}
    next_index = 0

    def schedule_one(index: int) -> None:
        tasks[index] = asyncio.create_task(
            _prepare_centra_person_frame(camera_ids[index], screenshot_ttl, ffmpeg))

    while next_index < min(prefetch, len(camera_ids)):
        schedule_one(next_index)
        next_index += 1
    try:
        for index in range(len(camera_ids)):
            position = index + 1
            if job.get("cancel_requested"):
                job.update(status="cancelled", stage="Остановлено")
                return
            camera_id, camera, path, prepare_error = await tasks.pop(index)
            if next_index < len(camera_ids):
                schedule_one(next_index)
                next_index += 1
            if prepare_error:
                record_failure(camera_id, prepare_error)
            else:
                try:
                    detection = await asyncio.to_thread(detect_people, path, CENTRA_PERSON_MODEL, confidence)
                    if detection["count"]:
                        ttl = max(300, min(86400, int(os.environ.get(
                            "IP2DOMAIN_CENTRA_REID_TTL", "7200"))))
                        states = await asyncio.to_thread(storage.load_centra_reid_states, ttl)
                        identities, changed_states = await asyncio.to_thread(
                            assign_identities_stateless, path, detection["detections"], camera_id, states)
                        await asyncio.to_thread(storage.save_centra_reid_states, changed_states)
                        job["matches"].append({"camera_id": camera_id,
                                               "id": camera_id,
                                               "confidence": round(detection["confidence"], 3),
                                               "people_count": detection["count"],
                                               "people": identities,
                                               "title": camera.get("title"),
                                               "address": camera.get("address"),
                                               "camera_type": camera.get("camera_type"),
                                               "entrance": camera.get("entrance"),
                                               "embed_url": str(camera.get("embed_url") or "").split("?", 1)[0],
                                               "screenshot_url": f"/api/cameras/centra/screens/{camera_id}.jpg"})
                        persisted_match = {key: value for key, value in job["matches"][-1].items()
                                           if key != "people"}
                        storage.save_centra_person_result(persisted_match)
                except Exception as exc:
                    record_failure(camera_id, str(exc))
            elapsed = max(0.001, time.time() - started_at)
            speed = position / elapsed
            remaining_pauses = max(0, (len(camera_ids) - position) // batch_size)
            eta_seconds = int((len(camera_ids) - position) / speed + remaining_pauses * batch_pause) if speed else None
            job.update(checked=position, progress_pct=int(position * 100 / len(camera_ids)),
                       speed=round(speed, 2), eta_seconds=eta_seconds,
                       stage=f"Проверено {position:,} из {len(camera_ids):,} · с людьми {len(job['matches'])}")
            await asyncio.sleep(0.05)
            if position < len(camera_ids) and position % batch_size == 0:
                job["stage"] = (f"Пачка {position // batch_size} завершена · пауза {batch_pause:g} сек. · "
                                f"проверено {position:,} из {len(camera_ids):,}")
                await asyncio.sleep(batch_pause)
    finally:
        for task in tasks.values():
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks.values(), return_exceptions=True)
    job.update(status="completed", progress_pct=100,
               stage=f"Готово · с людьми {len(job['matches'])} из {len(camera_ids)}")

@router.post("/api/cameras/centra/people")
async def start_centra_person_detection(req: CentraPersonDetectionRequest,
                                        background_tasks: BackgroundTasks):
    from ip2domain.core.person_detector import available
    if not available(CENTRA_PERSON_MODEL):
        raise HTTPException(status_code=503, detail="Модель обнаружения людей не установлена")
    if any(job.get("status") in {"queued", "running"} for job in CENTRA_PERSON_JOBS.values()):
        raise HTTPException(status_code=409, detail="Анализ людей уже выполняется")
    camera_type = req.camera_type.strip().upper()
    if camera_type and not re.fullmatch(r"[A-Z]", camera_type):
        raise HTTPException(status_code=400, detail="Некорректный тип камеры")
    if req.all_cameras:
        camera_ids = [str(camera.get("id") or "").upper()
                      for camera in storage.get_centra_cameras()
                      if camera.get("available", True)
                      and (not camera_type or str(camera.get("camera_type") or camera.get("id") or "")
                           .upper().startswith(f"{camera_type}-") or
                           str(camera.get("camera_type") or "").upper() == camera_type)]
    else:
        camera_ids = list(dict.fromkeys(camera_id.upper() for camera_id in req.camera_ids
                                         if re.fullmatch(r"[A-Z]-\d+-\d+", camera_id, re.IGNORECASE)))
    camera_ids = list(dict.fromkeys(camera_id for camera_id in camera_ids
                                    if re.fullmatch(r"[A-Z]-\d+-\d+", camera_id)))
    if not camera_ids:
        raise HTTPException(status_code=400, detail="Нет камер для анализа")
    job_id = uuid.uuid4().hex[:12]
    CENTRA_PERSON_JOBS[job_id] = {"job_id": job_id, "status": "queued", "stage": "В очереди",
                                  "total": len(camera_ids), "checked": 0, "progress_pct": 0,
                                  "matches": [], "failed": 0, "all_cameras": req.all_cameras,
                                  "failure_details": [],
                                  "camera_type": camera_type,
                                  "batch_size": 100, "screenshot_ttl": max(10, min(3600, int(
                                      os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300")))),
                                  "prefetch": max(1, min(12, int(os.environ.get(
                                      "IP2DOMAIN_CENTRA_PEOPLE_PREFETCH", "6")))),
                                  "eta_seconds": None}
    background_tasks.add_task(_run_centra_person_detection, job_id, camera_ids, req.confidence)
    return CENTRA_PERSON_JOBS[job_id]

@router.get("/api/cameras/centra/people/active")
def get_active_centra_person_detection():
    active = [job for job in CENTRA_PERSON_JOBS.values()
              if job.get("status") in {"queued", "running"}]
    if not active:
        return {"job": None}
    job = active[-1]
    return {"job": {key: job.get(key) for key in (
        "job_id", "status", "stage", "total", "checked", "progress_pct",
        "failed", "all_cameras", "camera_type", "eta_seconds", "matches_total")}}

@router.get("/api/cameras/centra/people/results")
def get_saved_centra_person_results(offset: int = Query(default=0, ge=0),
                                    limit: int = Query(default=100, ge=1, le=100),
                                    camera_type: str = Query(default="", max_length=1),
                                    search: str = Query(default="", max_length=200)):
    camera_type = camera_type.strip().upper()
    if camera_type and not re.fullmatch(r"[A-Z]", camera_type):
        raise HTTPException(status_code=400, detail="Некорректный тип камеры")
    page = storage.list_centra_person_results(offset, limit, camera_type, search)
    ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300"))))
    for camera in page["cameras"]:
        camera_id = str(camera.get("camera_id") or camera.get("id") or "").upper()
        camera["id"] = camera_id
        camera["screenshot_url"] = f"/api/cameras/centra/screens/{camera_id}.jpg"
        camera["screenshot_stale"] = _centra_capture_is_stale(
            CENTRA_CAPTURE_DIR / f"{camera_id}.jpg", ttl)
    page.update({"offset": offset, "limit": limit,
                 "has_more": offset + len(page["cameras"]) < page["total"]})
    return page

@router.get("/api/cameras/centra/people-identities/search")
def search_centra_person_identity(person_id: str = Query(min_length=8, max_length=30),
                                  camera_type: str = Query(default="", max_length=1)):
    person_id = person_id.strip().lower()
    if not re.fullmatch(r"person-\d+", person_id):
        raise HTTPException(status_code=400, detail="ID должен иметь вид person-2")
    camera_type = camera_type.strip().upper()
    if camera_type and not re.fullmatch(r"[A-Z]", camera_type):
        raise HTTPException(status_code=400, detail="Некорректный тип камеры")
    ttl = max(300, min(86400, int(os.environ.get("IP2DOMAIN_CENTRA_REID_TTL", "7200"))))
    state = storage.get_centra_reid_state(person_id, ttl)
    observations = list(state.get("observations") or []) if state else []
    cameras = []
    for observation in sorted(observations, key=lambda item: item["seen_at"], reverse=True):
        camera = storage.get_centra_camera(observation["camera_id"])
        if not camera:
            continue
        current_type = str(camera.get("camera_type") or observation["camera_id"][:1]).upper()
        if camera_type and current_type != camera_type:
            continue
        camera = dict(camera)
        camera.update({"people_count": 1, "person_search_id": person_id,
                       "person_similarity": observation["similarity"],
                       "detected_at": datetime.fromtimestamp(observation["seen_at"]).isoformat(
                           sep=" ", timespec="seconds"),
                       "screenshot_url": f"/api/cameras/centra/screens/{observation['camera_id']}.jpg"})
        cameras.append(camera)
    return {"person_id": person_id, "cameras": cameras, "total": len(cameras), "has_more": False}

@router.get("/api/cameras/centra/people/{job_id}")
def get_centra_person_detection(job_id: str,
                                matches_from: int = Query(default=0, ge=0)):
    job = CENTRA_PERSON_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Анализ не найден")
    matches = job.get("matches", [])
    return {**job, "matches": matches[matches_from:], "matches_total": len(matches)}

@router.post("/api/cameras/centra/people/{job_id}/cancel")
def cancel_centra_person_detection(job_id: str):
    job = CENTRA_PERSON_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Анализ не найден")
    job["cancel_requested"] = True
    return job

@router.post("/api/cameras/centra/people-identities/reset")
def reset_centra_person_identities():
    from ip2domain.core.person_reid import reset_identities
    reset_identities()
    deleted = storage.clear_centra_reid_states()
    return {"status": "ok", "deleted": deleted}

@router.get("/api/remote-desktop/capture/{capture_id}")
def get_remote_desktop_capture(capture_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", capture_id):
        raise HTTPException(status_code=404, detail="Снимок не найден")
    path = REMOTE_CAPTURE_DIR / f"{capture_id}.png"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Снимок не найден")
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "private, no-store"})
