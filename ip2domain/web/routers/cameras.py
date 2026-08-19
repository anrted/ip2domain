"""IP Camera Network Scanner, RTSP stream test, and Generic Camera Catalog endpoints."""
import asyncio
import csv
import io
import ipaddress
import logging
import os
import re
import shutil
import time
import uuid
from datetime import UTC, datetime
from typing import Dict, List, Literal, Optional
from urllib.parse import quote, urlparse
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from ip2domain.core.ip_parser import IPParser
from ip2domain.core.target_policy import validate_network_target, private_targets_allowed
from ip2domain.modules.camera_scanner import CameraScanner
from ip2domain.web.routers.common import (
    storage,
    camera_catalog,
    camera_providers,
    CAMERA_JOBS,
    CAMERA_CANCEL_EVENTS,
    CAMERA_CAPTURE_DIR,
    CAMERA_CAPTURE_LOCKS,
    CAMERA_PREVIEW_SEMAPHORE,
    CAMERA_SNAPSHOT_CACHE,
    IP_CAMERA_CONNECTIONS,
    IP_CAMERA_PREVIEW_LOCKS,
    IP_CAMERA_PREVIEW_SEMAPHORE,
    IP_CAMERA_STREAM_SEMAPHORE,
    COMMON_RTSP_PATHS,
    CENTRA_FFMPEG_SEMAPHORE,
    _centra_capture_is_stale,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["cameras"])

class CameraScanRequest(BaseModel):
    targets: str = Field(min_length=1, max_length=200000)
    ports: List[int] = Field(default_factory=lambda: CameraScanner.DEFAULT_PORTS.copy(), max_items=128)
    concurrency: int = Field(default=0, ge=0, le=32)

class IPCameraConnectionRequest(BaseModel):
    target: str = Field(min_length=2, max_length=45)
    port: int = Field(ge=1, le=65535)
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=512)
    rtsp_path: str = Field(default="/", min_length=1, max_length=512)

class CameraEndpointRequest(BaseModel):
    kind: Literal["snapshot", "hls", "rtsp"]
    url: str = Field(min_length=1, max_length=2048)
    priority: int = Field(default=0, ge=-1000, le=1000)

class CameraImportItem(BaseModel):
    external_id: str = Field(min_length=1, max_length=500)
    title: str = Field(default="", max_length=500)
    address: str = Field(default="", max_length=1000)
    camera_type: str = Field(default="ip", max_length=100)
    available: bool = True
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    endpoints: List[CameraEndpointRequest] = Field(default_factory=list, max_items=20)
    metadata: Dict[str, object] = Field(default_factory=dict)

class CameraImportRequest(BaseModel):
    cameras: List[CameraImportItem] = Field(min_items=1, max_items=1000)

async def _run_camera_job(job_id: str, req: CameraScanRequest, targets: List[str]):
    cancel_event = CAMERA_CANCEL_EVENTS.setdefault(job_id, asyncio.Event())
    found_targets = set()
    try:
        started = time.monotonic()
        limits = CameraScanner.resource_limits()
        effective_concurrency = min(req.concurrency or limits["nmap_concurrency"],
                                    limits["nmap_concurrency"])
        initial_stage = f"Подготовка {len(targets)} IP · Nmap-процессов: {effective_concurrency}"
        latest_progress = {"pct": 1, "stage": initial_stage}
        publish_lock = asyncio.Lock()
        CAMERA_JOBS.update(job_id, status="running", progress_pct=1, stage=initial_stage)

        def progress(pct: int, stage: str):
            latest_progress.update(pct=pct, stage=stage)
            CAMERA_JOBS.update(job_id, progress_pct=pct,
                               stage=f"{stage} · прошло {int(time.monotonic() - started)} сек.")

        async def device_found(device: dict):
            async with publish_lock:
                target = str(device.get("target") or "")
                if not target or target in found_targets:
                    return
                found_targets.add(target)
                storage.save_camera_devices([device])
                CAMERA_JOBS.update(
                    job_id, found=len(found_targets), devices_version=len(found_targets),
                )

        scan_task = asyncio.create_task(CameraScanner().scan(
            targets, req.ports, progress, device_found, cancel_event, req.concurrency))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=.5)
            if done:
                break
            job = CAMERA_JOBS.get(job_id) or {}
            if job.get("cancel_requested") or job.get("status") == "cancelling":
                cancel_event.set()
            CAMERA_JOBS.update(
                job_id, progress_pct=latest_progress["pct"],
                stage=f'{latest_progress["stage"]} · прошло {int(time.monotonic() - started)} сек.',
            )
        result = await scan_task
        storage.save_camera_devices(result.get("devices", []))
        result["devices"] = storage.get_camera_devices()
        result["camera_count"] = len(result["devices"])
        CAMERA_JOBS.update(job_id, status="completed", progress_pct=100,
                           stage="Проверка завершена", results=result)
    except asyncio.CancelledError:
        live_devices = storage.get_camera_devices()
        partial = {"target_count": len(targets), "devices": live_devices,
                   "camera_count": len(live_devices), "partial": True}
        CAMERA_JOBS.update(job_id, status="cancelled", cancel_requested=True,
                           stage=f"Остановлено · найдено {len(found_targets)}", results=partial)
    except Exception as exc:
        logger.error("Camera scan %s failed: %s", job_id, exc, exc_info=True)
        CAMERA_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")
    finally:
        CAMERA_CANCEL_EVENTS.pop(job_id, None)

@router.post("/api/cameras/scan")
async def start_camera_scan(req: CameraScanRequest, background_tasks: BackgroundTasks):
    try:
        specs = [item for item in re.split(r"[\s,;]+", req.targets.strip()) if item]
        targets, seen = [], set()
        max_targets = max(1, min(1000000, int(os.environ.get(
            "IP2DOMAIN_CAMERA_MAX_TARGETS", "262144"))))
        for spec in specs:
            remaining = max_targets - len(targets)
            if remaining <= 0:
                raise ValueError(f"Достигнут общий лимит задания: {max_targets:,} IP")
            try:
                parsed_targets = IPParser.parse_target(spec, max_ips=remaining)
                for target in parsed_targets:
                    if target not in seen:
                        seen.add(target)
                        targets.append(target)
            except ValueError as exc:
                expanded = re.search(r"Target expands to (\d+) IPs; maximum is (\d+)", str(exc))
                if expanded:
                    raise ValueError(
                        f"Диапазон {spec} содержит {int(expanded.group(1)):,} IP; "
                        f"в задание уже добавлено {len(targets):,}, общий лимит {max_targets:,}"
                    ) from exc
                raise
        if not targets:
            raise ValueError("Список IP-адресов пуст")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not private_targets_allowed():
        blocked = next((target for target in targets if not ipaddress.ip_address(target).is_global), None)
        if blocked:
            raise HTTPException(status_code=400, detail=f"Приватный или служебный IP запрещён: {blocked}")
    if not req.ports or any(port < 1 or port > 65535 for port in req.ports):
        raise HTTPException(status_code=400, detail="Порты должны находиться в диапазоне 1–65535")
    job_id = uuid.uuid4().hex[:12]
    limits = CameraScanner.resource_limits()
    effective_concurrency = min(req.concurrency or limits["nmap_concurrency"],
                                limits["nmap_concurrency"])
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} IP"
    CAMERA_JOBS.create(job_id, {"job_id": job_id, "target": target_label,
        "total_targets": len(targets), "status": "queued", "progress_pct": 0,
        "stage": "В очереди", "error": "", "found": 0, "devices_version": 0,
        "cancel_requested": False, "nmap_concurrency": effective_concurrency,
        "resource_limits": limits})
    CAMERA_CANCEL_EVENTS[job_id] = asyncio.Event()
    background_tasks.add_task(_run_camera_job, job_id, req, targets)
    return {"status": "queued", "job_id": job_id, "total_targets": len(targets)}

@router.get("/api/cameras/scan/{job_id}")
def get_camera_scan(job_id: str):
    job = CAMERA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job

@router.post("/api/cameras/scan/{job_id}/cancel")
async def cancel_camera_scan(job_id: str):
    job = CAMERA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    if job.get("status") not in {"queued", "running", "cancelling"}:
        return job
    CAMERA_JOBS.update(job_id, status="cancelling", cancel_requested=True,
                       stage="Остановка сканера...")
    event = CAMERA_CANCEL_EVENTS.get(job_id)
    if event:
        event.set()
    return CAMERA_JOBS.get(job_id)

@router.get("/api/cameras/results")
def get_camera_results():
    devices = storage.get_camera_devices()
    return {"devices": devices, "camera_count": len(devices)}

@router.get("/api/cameras/results/export.csv")
def export_camera_results_csv():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("ip_address", "hostname", "score", "confidence", "protocols", "ports", "updated_at"))

    def safe_cell(value) -> str:
        value = str(value or "")
        return "'" + value if value.startswith(("=", "+", "-", "@")) else value

    for device in storage.get_camera_devices(limit=250000):
        protocols, ports = set(), set()
        for service in device.get("services", []):
            name = str(service.get("service") or "").lower()
            port = int(service.get("port") or 0)
            if port:
                ports.add(port)
            scripts = " ".join(str(item.get("id") or "").lower() for item in service.get("scripts", []))
            if "rtsp" in name or "rtsp-methods" in scripts:
                protocols.add("RTSP")
            if "http" in name or port in {80, 443, 8000, 8080, 8081, 8443, 8899}:
                protocols.add("HTTPS" if service.get("tunnel") == "ssl" or "https" in name or port in {443, 8443} else "HTTP")
            if "onvif" in name or "onvif" in scripts:
                protocols.add("ONVIF")
        writer.writerow((safe_cell(device.get("target")), safe_cell(device.get("hostname")),
                         int(device.get("score") or 0), safe_cell(device.get("confidence")),
                         ",".join(sorted(protocols)), ",".join(map(str, sorted(ports))),
                         safe_cell(device.get("updated_at"))))
    filename = f"ip-cameras-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(content="\ufeff" + output.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "Cache-Control": "no-store"})

@router.delete("/api/cameras/results")
def clear_camera_results():
    return {"status": "cleared", "deleted": storage.clear_camera_devices()}

def _scanned_rtsp_camera(target: str, port: int) -> tuple:
    try:
        target = str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Некорректный IP камеры") from exc
    device = storage.get_camera_device(target)
    if not device:
        raise HTTPException(status_code=404, detail="Камера отсутствует в результатах сканера")
    service = next((item for item in device.get("services", [])
                    if int(item.get("port") or 0) == port and
                    (str(item.get("service") or "").lower() == "rtsp" or
                     any(str(script.get("id") or "") == "rtsp-methods"
                         for script in item.get("scripts", [])))), None)
    if not service:
        raise HTTPException(status_code=400, detail="У камеры не подтверждён RTSP на этом порту")
    return target, device, service

def _cleanup_ip_camera_connections() -> None:
    now = time.time()
    for connection_id, connection in list(IP_CAMERA_CONNECTIONS.items()):
        if float(connection.get("expires_at") or 0) <= now:
            IP_CAMERA_CONNECTIONS.pop(connection_id, None)

@router.post("/api/cameras/connect/session")
def create_scanned_camera_connection(req: IPCameraConnectionRequest):
    target, _, _ = _scanned_rtsp_camera(req.target, req.port)
    rtsp_path = req.rtsp_path.strip()
    if rtsp_path.lower().startswith("rtsp://"):
        parsed = urlparse(rtsp_path)
        try:
            url_host = str(ipaddress.ip_address(parsed.hostname or ""))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="RTSP URL должен содержать IP камеры") from exc
        url_port = parsed.port or 554
        if parsed.username or parsed.password:
            raise HTTPException(status_code=400, detail="Логин и пароль вводятся в отдельных полях")
        if url_host != target or url_port != req.port:
            raise HTTPException(status_code=400, detail="IP и порт RTSP URL должны совпадать с выбранной камерой")
        rtsp_path = parsed.path or "/"
        if parsed.query:
            rtsp_path += f"?{parsed.query}"
    if (rtsp_path != "auto" and (not rtsp_path.startswith("/") or "//" in rtsp_path or
            any(ord(character) < 32 for character in rtsp_path))):
        raise HTTPException(status_code=400, detail="RTSP-путь должен начинаться с / и не содержать управляющих символов")
    _cleanup_ip_camera_connections()
    connection_id = uuid.uuid4().hex
    ttl = max(60, min(3600, int(os.environ.get("IP2DOMAIN_IP_CAMERA_SESSION_TTL", "900"))))
    IP_CAMERA_CONNECTIONS[connection_id] = {
        "target": target, "port": req.port, "username": req.username,
        "password": req.password, "rtsp_path": rtsp_path,
        "expires_at": time.time() + ttl,
    }
    return {"connection_id": connection_id, "expires_in": ttl}

@router.delete("/api/cameras/connect/session/{connection_id}")
def close_scanned_camera_connection(connection_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", connection_id):
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    existed = IP_CAMERA_CONNECTIONS.pop(connection_id, None) is not None
    return {"status": "closed", "existed": existed}

@router.get("/api/cameras/connect/session/{connection_id}")
def get_scanned_camera_connection(connection_id: str):
    _cleanup_ip_camera_connections()
    connection = IP_CAMERA_CONNECTIONS.get(connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    return {"target": connection["target"], "port": connection["port"],
            "rtsp_path": connection.get("rtsp_path"),
            "selected_rtsp_path": connection.get("selected_rtsp_path")}

def _active_ip_camera_connection(connection_id: str, target: str, port: int) -> dict:
    _cleanup_ip_camera_connections()
    connection = IP_CAMERA_CONNECTIONS.get(connection_id)
    if not connection or connection["target"] != target or int(connection["port"]) != port:
        raise HTTPException(status_code=401, detail="Сессия подключения истекла или недействительна")
    connection["expires_at"] = time.time() + max(60, min(3600, int(
        os.environ.get("IP2DOMAIN_IP_CAMERA_SESSION_TTL", "900"))))
    return connection

@router.get("/api/cameras/connect/snapshot.jpg")
async def get_scanned_camera_snapshot(target: str = Query(min_length=2, max_length=45),
                                      port: int = Query(ge=1, le=65535),
                                      refresh: bool = False,
                                      connection_id: str = Query(default="", max_length=32)):
    target, _, _ = _scanned_rtsp_camera(target, port)
    username = password = ""
    rtsp_path = "/"
    if connection_id:
        connection = _active_ip_camera_connection(connection_id, target, port)
        username, password = str(connection.get("username") or ""), str(connection.get("password") or "")
        rtsp_path = str(connection.get("rtsp_path") or "/")
    allowed, _ = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail="IP запрещён сетевой политикой")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise HTTPException(status_code=503, detail="Для RTSP-предпросмотра требуется FFmpeg")
    cache_scope = connection_id or "anonymous"
    cache_key = uuid.uuid5(uuid.NAMESPACE_URL, f"scanner:{target}:{port}:{cache_scope}").hex
    directory = CAMERA_CAPTURE_DIR / "scanner"
    directory.mkdir(parents=True, exist_ok=True)
    path, temporary = directory / f"{cache_key}.jpg", directory / f"{cache_key}.tmp.jpg"
    ttl = max(2, min(30, int(os.environ.get("IP2DOMAIN_IP_CAMERA_PREVIEW_TTL", "5"))))
    if path.is_file() and not refresh and time.time() - path.stat().st_mtime < ttl:
        return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=2"})
    lock = IP_CAMERA_PREVIEW_LOCKS.setdefault(cache_key, asyncio.Lock())
    async with lock:
        if path.is_file() and not refresh and time.time() - path.stat().st_mtime < ttl:
            return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=2"})
        if connection_id:
            current_connection = IP_CAMERA_CONNECTIONS.get(connection_id)
            if current_connection:
                rtsp_path = str(current_connection.get("rtsp_path") or rtsp_path)
        temporary.unlink(missing_ok=True)
        host = f"[{target}]" if ":" in target else target
        credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
        candidate_paths = COMMON_RTSP_PATHS if rtsp_path == "auto" else (rtsp_path,)
        errors = []
        selected_path = None
        probe_timeout = max(3, min(12, int(os.environ.get("IP2DOMAIN_RTSP_PATH_PROBE_TIMEOUT", "6"))))
        for candidate_path in candidate_paths:
            temporary.unlink(missing_ok=True)
            source = f"rtsp://{credentials}{host}:{port}{candidate_path}"
            async with IP_CAMERA_PREVIEW_SEMAPHORE:
                process = await asyncio.create_subprocess_exec(
                    ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                    "-rtsp_transport", "tcp", "-timeout", f"{probe_timeout * 1000000}", "-i", source,
                    "-frames:v", "1", "-vf", "scale=min(960\\,iw):-2", "-q:v", "4",
                    "-update", "1", str(temporary), stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE)
                try:
                    _, error = await asyncio.wait_for(process.communicate(), timeout=probe_timeout + 2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.communicate()
                    errors.append(f"{candidate_path}: timeout")
                    continue
            if process.returncode == 0 and temporary.is_file():
                selected_path = candidate_path
                break
            message = error.decode(errors="replace").replace(source, f"rtsp://{host}:{port}{candidate_path}")[-160:].strip()
            errors.append(f"{candidate_path}: {message or 'недоступен'}")
        if not selected_path:
            raise HTTPException(status_code=502, detail="Рабочий RTSP-путь не найден · " + " | ".join(errors[-3:]))
        if connection_id and rtsp_path == "auto":
            connection["rtsp_path"] = selected_path
            connection["selected_rtsp_path"] = selected_path
        os.replace(temporary, path)
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=2"})

@router.get("/api/cameras/connect/stream.mjpeg")
async def stream_scanned_camera(target: str = Query(min_length=2, max_length=45),
                                port: int = Query(ge=1, le=65535),
                                connection_id: str = Query(min_length=32, max_length=32)):
    target, _, _ = _scanned_rtsp_camera(target, port)
    connection = _active_ip_camera_connection(connection_id, target, port)
    rtsp_path = str(connection.get("selected_rtsp_path") or connection.get("rtsp_path") or "")
    if not rtsp_path or rtsp_path == "auto":
        raise HTTPException(status_code=409, detail="Сначала получите кадр для определения RTSP-пути")
    allowed, _ = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail="IP запрещён сетевой политикой")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise HTTPException(status_code=503, detail="Для видео требуется FFmpeg")
    host = f"[{target}]" if ":" in target else target
    username, password = str(connection.get("username") or ""), str(connection.get("password") or "")
    credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
    source = f"rtsp://{credentials}{host}:{port}{rtsp_path}"
    fps = max(1, min(15, int(os.environ.get("IP2DOMAIN_IP_CAMERA_STREAM_FPS", "5"))))
    width = max(320, min(1280, int(os.environ.get("IP2DOMAIN_IP_CAMERA_STREAM_WIDTH", "640"))))

    async def generate():
        process = None
        await IP_CAMERA_STREAM_SEMAPHORE.acquire()
        try:
            process = await asyncio.create_subprocess_exec(
                ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
                "-rtsp_transport", "tcp", "-timeout", "8000000", "-i", source,
                "-an", "-vf", f"fps={fps},scale={width}:-2", "-q:v", "6",
                "-f", "mpjpeg", "-boundary_tag", "ip2domainframe", "pipe:1",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            while True:
                chunk = await process.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            if process and process.returncode is None:
                process.kill()
                await process.wait()
            IP_CAMERA_STREAM_SEMAPHORE.release()

    return StreamingResponse(generate(), media_type="multipart/x-mixed-replace;boundary=ip2domainframe",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

@router.get("/api/camera-providers")
def get_camera_providers():
    return {"providers": camera_providers.describe()}

@router.get("/api/camera-catalog")
def get_camera_catalog(offset: int = Query(default=0, ge=0),
                       limit: int = Query(default=100, ge=1, le=500),
                       provider_id: str = Query(default="", max_length=100),
                       camera_type: str = Query(default="", max_length=100),
                       search: str = Query(default="", max_length=200),
                       include_unavailable: bool = False):
    if provider_id and not camera_providers.get(provider_id):
        raise HTTPException(status_code=404, detail="Провайдер камер не найден")
    return storage.list_cameras(offset, limit, provider_id, camera_type, search,
                                available_only=not include_unavailable)

@router.get("/api/camera-catalog/{provider_id}/{external_id}")
def get_catalog_camera(provider_id: str, external_id: str):
    if not camera_providers.get(provider_id):
        raise HTTPException(status_code=404, detail="Провайдер камер не найден")
    camera = camera_catalog.get(provider_id, external_id)
    if not camera:
        raise HTTPException(status_code=404, detail="Камера не найдена")
    return camera

@router.get("/api/camera-catalog/{provider_id}/{external_id}/analysis")
def get_catalog_camera_analysis(provider_id: str, external_id: str,
                                analysis_type: str = Query(default="", max_length=100),
                                limit: int = Query(default=100, ge=1, le=500)):
    camera = camera_catalog.get(provider_id, external_id)
    if not camera:
        raise HTTPException(status_code=404, detail="Камера не найдена")
    return {"camera_uid": camera["uid"], "results": storage.list_camera_analysis(
        camera["uid"], analysis_type, limit)}

@router.post("/api/camera-providers/{provider_id}/cameras", status_code=201)
def import_provider_cameras(provider_id: str, req: CameraImportRequest):
    if provider_id == "centra":
        raise HTTPException(status_code=400, detail="Centra наполняется через discovery API")
    if not camera_providers.get(provider_id):
        raise HTTPException(status_code=404, detail="Провайдер камер не найден")
    try:
        cameras = camera_catalog.upsert(provider_id, [item.dict() for item in req.cameras])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"provider_id": provider_id, "imported": len(cameras), "cameras": cameras}
