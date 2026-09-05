"""Centra Gateway Router and Facade.

Decomposed modular architecture:
- ip2domain.cameras.centra_engine.models: Request schemas
- ip2domain.cameras.centra_engine.geo: Address parsing & DaData geocoding
- ip2domain.cameras.centra_engine.screens: Snapshot & frame capture engine
- ip2domain.cameras.centra_engine.discovery: Camera discovery & probes
- ip2domain.cameras.centra_engine.people: Person detection & Re-ID analysis
"""
import asyncio
import logging
import os
import re
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import aiohttp
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse

from ip2domain.cameras.centra_engine.models import (
    CentraDiscoveryRequest,
    CentraCoordinatesRequest,
    CentraPersonDetectionRequest,
    CentraGeocodeRequest,
)
from ip2domain.cameras.centra_engine.geo import (
    DEFAULT_CENTRA_CAMERAS,
    _centra_cameras,
    _centra_address,
    _centra_address_override,
    _dadata_address,
    _centra_locality,
    _dadata_queries,
)
from ip2domain.cameras.centra_engine.screens import (
    _cleanup_centra_captures,
    _centra_capture_is_stale,
    _generate_centra_screenshot,
    _refresh_centra_screenshot,
    _prepare_centra_person_frame,
    _generate_generic_ip_screenshot,
)
from ip2domain.cameras.centra_engine.discovery import (
    _centra_discovery_types,
    _run_centra_discovery,
)
from ip2domain.cameras.centra_engine.people import (
    _run_centra_person_detection,
)
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


@router.get("/api/cameras/centra")
def get_centra_cameras(source: str = Query(default="centra", max_length=50)):
    if hasattr(source, "default"):
        raw_source = getattr(source, "default", "centra")
    else:
        raw_source = source
    source_val = str(raw_source or "centra").strip().lower()
    cameras = []

    # 1. Centra Cameras
    if source_val in {"all", "centra"}:
        stored = storage.get_centra_cameras()
        centra_list = ([camera for camera in stored if camera.get("available", True)]
                       if stored else _centra_cameras())
        for camera in centra_list:
            camera["address"] = _centra_address(camera.get("title") or camera.get("address", ""))
            embed_url = str(camera.get("embed_url") or "")
            if "/embed.html" in embed_url:
                camera["embed_url"] = embed_url.split("?", 1)[0]
            camera["provider_id"] = "centra"
        cached = storage.get_centra_coordinates([camera.get("address", "") for camera in centra_list])
        for camera in centra_list:
            if camera.get("address") in cached:
                camera["coordinates"] = cached[camera["address"]]
        cameras.extend(centra_list)

    # 2. Orion Telecom Public Cameras (cam.krk.ru)
    if source_val in {"all", "orion"}:
        try:
            orion_cams = storage.list_cameras(limit=500, provider_id="orion", available_only=True).get("cameras", [])
            if not orion_cams:
                # Lazy-fetch open cameras and populate catalog
                from ip2domain.cameras.orion import OrionProvider
                raw_orion = OrionProvider.fetch_public_cameras()
                if raw_orion:
                    provider = OrionProvider()
                    normalized = [provider.normalize(item).to_dict() for item in raw_orion if item.get("latitude") and item.get("longitude")]
                    storage.save_cameras("orion", normalized)
                    orion_cams = storage.list_cameras(limit=500, provider_id="orion", available_only=True).get("cameras", [])
            for c in orion_cams:
                c_id = str(c.get("external_id") or c.get("id"))
                cameras.append({
                    "id": f"ORION-{c_id}",
                    "external_id": c_id,
                    "title": c.get("title") or f"Орион {c_id}",
                    "address": c.get("address") or c.get("title") or "",
                    "camera_type": "ORION",
                    "available": True,
                    "provider_id": "orion",
                    "pin_color": "yellow",
                    "coordinates": [c.get("latitude"), c.get("longitude")] if c.get("latitude") and c.get("longitude") else None,
                    "embed_url": f"http://fluserver.orionnet.online/cam{c_id}/embed.html?autoplay=true&dvr=true",
                    "stream_url": f"http://fluserver.orionnet.online/cam{c_id}/index.m3u8",
                    "snapshot_url": f"http://fluserver.orionnet.online/cam{c_id}/preview.jpg",
                })
        except Exception as e:
            logger.warning(f"Failed to fetch Orion cameras for map: {e}")

    # A42 cameras (only if explicitly requested via source=a42 and present in DB)
    if source_val == "a42":
        try:
            a42_cams = storage.list_cameras(limit=500, provider_id="a42", available_only=True).get("cameras", [])
            for c in a42_cams:
                c_id = str(c.get("external_id") or c.get("id"))
                sldp_ep = next((ep.get("url") for ep in c.get("endpoints", []) if ep.get("kind") == "rtsp"), "")
                cameras.append({
                    "id": f"A42-{c_id}",
                    "external_id": c_id,
                    "title": c.get("title") or f"Дорожная камера {c_id}",
                    "address": c.get("address") or c.get("title") or "",
                    "camera_type": "A42",
                    "available": True,
                    "provider_id": "a42",
                    "pin_color": "pink",
                    "coordinates": [c.get("latitude"), c.get("longitude")] if c.get("latitude") and c.get("longitude") else None,
                    "embed_url": f"https://pdd.a42.ru/camera/{c_id}",
                    "stream_url": sldp_ep,
                    "snapshot_url": "",
                })
        except Exception as e:
            logger.warning(f"Failed to fetch A42 cameras: {e}")

    def camera_order(camera):
        c_id = str(camera.get("id", ""))
        match = re.fullmatch(r"([A-Z])-(\d+)-(\d+)", c_id, re.IGNORECASE)
        if match:
            return (0, int(match.group(2)), int(match.group(3)), match.group(1).upper())
        return (1, 0, 0, c_id)

    cameras.sort(key=camera_order)
    used_pin_colors = {"red": "I", "blue": "G", "green": "H/P", "yellow": "ORION"}
    type_pin_colors = {"I": "red", "G": "blue", "H": "green", "P": "green", "ORION": "yellow"}

    stored_list = stored if source_val in {"all", "centra"} else []
    for camera in (stored_list or cameras):
        camera_type = str(camera.get("camera_type") or camera.get("id", "")).split("-", 1)[0].upper()
        color = type_pin_colors.get(camera_type) or str(camera.get("pin_color") or "violet")
        if camera_type and color:
            used_pin_colors.setdefault(color, camera_type)
            type_pin_colors[camera_type] = color

    for camera in cameras:
        camera_type = str(camera.get("camera_type") or camera.get("id", "")).split("-", 1)[0].upper()
        color = type_pin_colors.get(camera_type) or str(camera.get("pin_color") or "violet")
        camera["pin_color"] = color

    return {
        "cameras": cameras,
        "source": source_val,
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
        raise HTTPException(status_code=502, detail=f"Ошибка соединения с DaData: {exc}") from exc
    raise HTTPException(status_code=404, detail="Адрес не найден в DaData")


@router.post("/api/cameras/centra/discover")
async def start_centra_discovery(req: CentraDiscoveryRequest, background_tasks: BackgroundTasks):
    camera_types = _centra_discovery_types(req.camera_type)
    if req.base_url:
        parsed = urlparse(req.base_url)
        hostname = (parsed.hostname or "").lower()
        is_mycentra = (
            hostname.endswith(".mycentra.ru")
            and bool(hostname[:-12])
            and all(c.isalnum() or c == "-" for c in hostname[:-12])
        )
        if (parsed.scheme != "https" or not is_mycentra
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
    if req.skip_existing and len(camera_types) > 1 and req.camera_type not in {"ALL", "KNOWN", "ALL_KNOWN"}:
        excluded_types = [camera_type for camera_type in camera_types if camera_type in saved_types]
        camera_types = [camera_type for camera_type in camera_types if camera_type not in saved_types]
        if not camera_types:
            raise HTTPException(status_code=400, detail="Все выбранные типы уже имеют найденные камеры в базе")

    palette = ["red", "blue", "green", "orange", "yellow", "violet", "pink", "gray"]
    for i, ctype in enumerate(camera_types):
        if ctype not in type_colors:
            type_colors[ctype] = palette[i % len(palette)]
    color_owners = {camera_type for camera_type, color in type_colors.items() if color == req.pin_color}
    new_types = [camera_type for camera_type in camera_types if camera_type not in type_colors]
    if len(camera_types) == 1 and new_types and color_owners:
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
        escaped_type = re.escape(camera_type)
        skipped = sum(1 for camera_id in known_ids if camera_id and
            (match := re.fullmatch(rf"{escaped_type}-(\d+)-(\d+)", camera_id, re.IGNORECASE)) and
            req.start_id <= int(match.group(1)) <= req.end_id and
            req.entrance_start <= int(match.group(2)) <= req.entrance_end)
        totals.append((camera_type, possible_per_type - skipped, skipped))
    total = sum(item[1] for item in totals)
    scan_limit = int(os.environ.get("IP2DOMAIN_CENTRA_SCAN_LIMIT", "0"))
    if scan_limit > 0 and total > scan_limit:
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
    safe_camera_id = re.sub(r"[^A-Za-z0-9_\-]", "", camera_id).upper()
    camera = storage.get_centra_camera(safe_camera_id)
    if not camera or not camera.get("available", True):
        raise HTTPException(status_code=404, detail="Камера не найдена")
    _cleanup_centra_captures()
    ffmpeg = shutil.which("ffmpeg")
    base_dir = CENTRA_CAPTURE_DIR.resolve()
    resolved_path = (base_dir / f"{safe_camera_id}.jpg").resolve()
    if not resolved_path.is_relative_to(base_dir):
        raise HTTPException(status_code=400, detail="Некорректный путь")
    path = resolved_path
    ttl = max(10, min(3600, int(os.environ.get("IP2DOMAIN_CENTRA_SCREEN_TTL", "300"))))
    if refresh and safe_camera_id in CENTRA_CAPTURE_REFRESH_TASKS:
        await CENTRA_CAPTURE_REFRESH_TASKS[safe_camera_id]
        if path.is_file():
            return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    if refresh and path.is_file() and time.time() - path.stat().st_mtime < ttl:
        return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    if path.is_file() and not refresh:
        if time.time() - path.stat().st_mtime >= ttl and safe_camera_id not in CENTRA_CAPTURE_REFRESH_TASKS:
            task = asyncio.create_task(_refresh_centra_screenshot(safe_camera_id, camera, path, ffmpeg))
            CENTRA_CAPTURE_REFRESH_TASKS[safe_camera_id] = task
            task.add_done_callback(lambda _task, key=safe_camera_id: CENTRA_CAPTURE_REFRESH_TASKS.pop(key, None))
        return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})
    await _generate_centra_screenshot(safe_camera_id, camera, path, ffmpeg)
    return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=15"})


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
