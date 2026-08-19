"""Remote Desktop Scanner (RDP / VNC) API endpoints."""
import asyncio
import ipaddress
import logging
import re
import time
import uuid
from typing import List
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from ip2domain.core.ip_parser import IPParser
from ip2domain.core.target_policy import private_targets_allowed
from ip2domain.modules.remote_desktop_scanner import RemoteDesktopScanner
from ip2domain.web.routers.common import storage, REMOTE_DESKTOP_JOBS, REMOTE_CAPTURE_DIR

logger = logging.getLogger(__name__)
router = APIRouter(tags=["remote-desktop"])

class RemoteDesktopScanRequest(BaseModel):
    targets: str = Field(min_length=1, max_length=200000)
    scan_rdp: bool = True
    scan_vnc: bool = True
    rdp_ports: List[int] = Field(default_factory=lambda: [3389], max_items=32)
    vnc_ports: List[int] = Field(default_factory=lambda: list(range(5900, 5911)), max_items=64)

async def _run_remote_desktop_job(job_id: str, req: RemoteDesktopScanRequest, targets: List[str]):
    try:
        started = time.monotonic()
        latest_progress = {"pct": 1, "stage": f"Подготовка {len(targets)} IP"}
        REMOTE_DESKTOP_JOBS.update(job_id, status="running", progress_pct=1,
                                   stage=latest_progress["stage"])

        def progress(pct: int, stage: str):
            latest_progress["pct"] = pct
            latest_progress["stage"] = stage
            REMOTE_DESKTOP_JOBS.update(job_id, progress_pct=pct,
                                       stage=f"{stage} · прошло {int(time.monotonic() - started)} сек.")

        scanner = RemoteDesktopScanner(REMOTE_CAPTURE_DIR)
        scan_task = asyncio.create_task(scanner.scan(
            targets, req.scan_rdp, req.scan_vnc, req.rdp_ports, req.vnc_ports, progress
        ))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=2)
            if done:
                break
            REMOTE_DESKTOP_JOBS.update(
                job_id,
                progress_pct=latest_progress["pct"],
                stage=(f"{latest_progress['stage']} · "
                       f"прошло {int(time.monotonic() - started)} сек."),
            )
        result = await scan_task
        storage.save_remote_desktop_services(result.get("services", []))
        result["services"] = storage.get_remote_desktop_services()
        REMOTE_DESKTOP_JOBS.update(job_id, status="completed", progress_pct=100,
                                   stage="Проверка завершена", results=result)
    except Exception as exc:
        logger.error("Remote desktop scan %s failed: %s", job_id, exc, exc_info=True)
        REMOTE_DESKTOP_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")

@router.post("/api/remote-desktop/scan")
async def start_remote_desktop_scan(req: RemoteDesktopScanRequest, background_tasks: BackgroundTasks):
    try:
        specs = [item for item in re.split(r"[\s,;]+", req.targets.strip()) if item]
        targets = []
        seen = set()
        max_targets = 65536
        for spec in specs:
            for target in IPParser.parse_target(spec, max_ips=max_targets - len(targets)):
                if target not in seen:
                    seen.add(target)
                    targets.append(target)
                    if len(targets) > max_targets:
                        raise ValueError(f"Одно задание может содержать не более {max_targets} IP")
        if not targets:
            raise ValueError("Список IP-адресов пуст")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not private_targets_allowed():
        blocked = next((target for target in targets if not ipaddress.ip_address(target).is_global), None)
        if blocked:
            raise HTTPException(status_code=400, detail=f"Приватный или служебный IP запрещён: {blocked}")
    for port in req.rdp_ports + req.vnc_ports:
        if port < 1 or port > 65535:
            raise HTTPException(status_code=400, detail="Порты должны находиться в диапазоне 1–65535")
    if not req.scan_rdp and not req.scan_vnc:
        raise HTTPException(status_code=400, detail="Выберите RDP или VNC")
    job_id = uuid.uuid4().hex[:12]
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} IP"
    REMOTE_DESKTOP_JOBS.create(job_id, {"job_id": job_id, "target": target_label,
        "total_targets": len(targets),
        "status": "queued", "progress_pct": 0, "stage": "В очереди", "error": ""})
    background_tasks.add_task(_run_remote_desktop_job, job_id, req, targets)
    return {"status": "queued", "job_id": job_id, "total_targets": len(targets)}

@router.get("/api/remote-desktop/scan/{job_id}")
def get_remote_desktop_scan(job_id: str):
    job = REMOTE_DESKTOP_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job

@router.get("/api/remote-desktop/results")
def get_remote_desktop_results():
    services = storage.get_remote_desktop_services()
    return {"services": services, "service_count": len(services)}

@router.delete("/api/remote-desktop/results")
def clear_remote_desktop_results():
    return {"status": "cleared", "deleted": storage.clear_remote_desktop_services()}
