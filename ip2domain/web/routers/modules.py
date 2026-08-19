"""Modules: Nmap, Vulnerability (Nikto/NSE), and HTTP Tech Stack analysis API."""
import asyncio
import ipaddress
import logging
import time
import uuid
from typing import Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from ip2domain.core.target_policy import validate_network_target
from ip2domain.modules.nmap_scanner import NmapScanner
from ip2domain.modules.vuln_scanner import VulnScanner
from ip2domain.modules.http_analyzer import HTTPTechAnalyzer
from ip2domain.web.routers.common import storage, VULN_JOBS, HTTP_CACHE

logger = logging.getLogger(__name__)
router = APIRouter(tags=["modules"])

class VulnKnownPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service: str = Field(default="", max_length=100)
    version: str = Field(default="", max_length=300)
    tunnel: str = Field(default="", max_length=20)
    http_detected: bool = False
    service_confidence: int = Field(default=0, ge=0, le=10)
    cpe: str = Field(default="", max_length=300)

class VulnScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: str = "ip"
    tech_stack: Optional[List[str]] = None
    open_ports: Optional[List[VulnKnownPort]] = Field(default=None, max_items=100)

def _merge_nmap_stack(target: str, analysis: Dict[str, any]) -> Dict[str, any]:
    """Merge persisted Nmap -sV fingerprints into an HTTP technology report."""
    nmap_stack = set()
    try:
        target_ip = str(ipaddress.ip_address(target))
    except ValueError:
        target_ip = None

    for item in storage.get_global_scan_results():
        applies = item.get("ip") == target_ip if target_ip else any(
            domain == target or domain.endswith("." + target)
            for domain in item.get("domains", [])
        )
        if applies:
            nmap_stack.update(item.get("nmap_tech_stack", []))

    merged = dict(analysis)
    http_stack = list(analysis.get("tech_stack", []))
    merged["tech_sources"] = {"http": http_stack, "nmap": sorted(nmap_stack, key=str.casefold)}
    merged["tech_stack"] = NmapScanner.normalize_tech_stack(set(http_stack) | nmap_stack)
    return merged

async def _run_vuln_scan_job(vuln_job_id: str, target: str, tech_stack: Optional[List[str]] = None,
                             open_ports: Optional[List[dict]] = None):
    try:
        stage_text = "Выполнение сканирования Nmap NSE и Nikto..."
        if tech_stack:
            stage_text = f"Сканирование Nmap NSE & Nikto (стек: {', '.join(tech_stack[:3])})..."

        VULN_JOBS.update(vuln_job_id,
            status="running",
            progress_pct=15,
            stage=stage_text,
        )

        scanner = VulnScanner()
        scan_started = time.monotonic()
        latest_progress = {"pct": 5, "stage": stage_text}

        def _on_progress(pct: int, msg: str):
            latest_progress.update(pct=pct, stage=msg)
            elapsed = int(time.monotonic() - scan_started)
            VULN_JOBS.update(vuln_job_id, progress_pct=pct, stage=f"{msg} · прошло {elapsed} сек.")

        scan_task = asyncio.create_task(scanner.scan_target_combined(
            target=target,
            tech_stack=tech_stack,
            known_ports=open_ports,
            progress_callback=_on_progress,
            use_cache=False,
        ))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=2)
            if done:
                break
            elapsed = int(time.monotonic() - scan_started)
            VULN_JOBS.update(
                vuln_job_id,
                progress_pct=latest_progress["pct"],
                stage=f"{latest_progress['stage']} · прошло {elapsed} сек.",
            )
        res = await scan_task

        VULN_JOBS.update(vuln_job_id,
            results=res,
            status="completed",
            progress_pct=100,
            stage="Поиск уязвимостей завершен!",
        )

        storage.save_vuln_analysis(target, res)
    except Exception as e:
        logger.error(f"Vuln scan job {vuln_job_id} failed for target {target}: {e}", exc_info=True)
        VULN_JOBS.update(vuln_job_id, status="error", error=str(e))

@router.post("/api/vuln/scan")
async def start_vuln_scan(req: VulnScanRequest, background_tasks: BackgroundTasks):
    target_clean = req.target.strip()
    allowed, normalized = await validate_network_target(target_clean)
    if not allowed:
        raise HTTPException(status_code=400, detail=normalized)
    target_clean = normalized
    active_count = sum(1 for _, job in VULN_JOBS.items()
                       if job.get("status") in ("queued", "running"))
    if active_count >= 2:
        raise HTTPException(status_code=429, detail="Too many active vulnerability scan jobs")

    for j_id, job in VULN_JOBS.items():
        if job["target"] == target_clean and job["status"] in ("queued", "running"):
            return {
                "status": "already_running",
                "job_id": j_id,
                "message": f"Сканирование уязвимостей для {target_clean} уже выполняется!"
            }

    tech_stack = req.tech_stack
    if not tech_stack:
        if target_clean in HTTP_CACHE and HTTP_CACHE[target_clean].get("tech_stack"):
            tech_stack = HTTP_CACHE[target_clean]["tech_stack"]
        else:
            db_http = storage.get_http_analysis(target_clean)
            if db_http and db_http.get("tech_stack"):
                tech_stack = db_http["tech_stack"]

    merged_analysis = _merge_nmap_stack(target_clean, {"tech_stack": tech_stack or []})
    tech_stack = merged_analysis["tech_stack"]
    open_ports = [port.dict() for port in (req.open_ports or [])]

    vuln_job_id = str(uuid.uuid4())[:8]
    VULN_JOBS.create(vuln_job_id, {
        "job_id": vuln_job_id,
        "target": target_clean,
        "target_type": req.target_type,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "status": "queued",
        "progress_pct": 5,
        "stage": "Инициализация сканера уязвимостей...",
        "results": None,
        "error": None,
    })

    background_tasks.add_task(_run_vuln_scan_job, vuln_job_id, target_clean, tech_stack, open_ports)
    return {"status": "queued", "job_id": vuln_job_id, "tech_stack": tech_stack, "open_ports": open_ports}

@router.get("/api/vuln/scan/{job_id}")
def get_vuln_scan_status(job_id: str):
    job = VULN_JOBS.get(job_id)
    if job:
        if job.get("status") == "completed" and not job.get("results") and job.get("target"):
            saved = storage.get_vuln_analysis(job["target"])
            if saved:
                job = dict(job)
                job["results"] = saved
        return job
    raise HTTPException(status_code=404, detail="Vulnerability scan job not found")

@router.get("/api/vuln/check/{target}")
async def check_vuln_scan_target(target: str):
    allowed, target_clean = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=target_clean)

    for j_id, job in VULN_JOBS.items():
        if job["target"] == target_clean and job["status"] in ("queued", "running"):
            return job

    db_saved = storage.get_vuln_analysis(target_clean)
    if db_saved:
        return {
            "status": "completed",
            "target": target_clean,
            "results": db_saved,
        }

    return {"status": "idle", "target": target_clean}

@router.get("/api/http/analyze/{target}")
async def analyze_http_tech(target: str, force: bool = Query(False)):
    allowed, target_clean = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=target_clean)

    if not force:
        if target_clean in HTTP_CACHE:
            return _merge_nmap_stack(target_clean, HTTP_CACHE[target_clean])

        db_saved = storage.get_http_analysis(target_clean)
        if db_saved:
            HTTP_CACHE[target_clean] = db_saved
            return _merge_nmap_stack(target_clean, db_saved)

    analyzer = HTTPTechAnalyzer(timeout=7)
    res = await analyzer.analyze_target(target_clean)

    HTTP_CACHE[target_clean] = res
    storage.save_http_analysis(target_clean, res)
    return _merge_nmap_stack(target_clean, res)
