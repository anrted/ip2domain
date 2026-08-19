"""Core Recon, Domain/IP Discovery, and Graph API endpoints."""
import asyncio
import ipaddress
import logging
import time
import uuid
from typing import Dict, List, Literal, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from ip2domain.core.ip_parser import IPParser
from ip2domain.core.engine import LookupEngine
from ip2domain.core.domain_recon import DomainReconEngine
from ip2domain.core.verifier import DomainVerifier
from ip2domain.core.graph_builder import GraphBuilder
from ip2domain.core.idn_utils import decode_punycode
from ip2domain.core.target_policy import validate_network_target, private_targets_allowed
from ip2domain.providers.manager import ProviderManager, AVAILABLE_PROVIDERS
from ip2domain.modules.nmap_scanner import NmapScanner, SCAN_PROFILES
from ip2domain.web.routers.common import storage, JOBS

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon"])

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=1024)
    providers: Optional[List[str]] = ["all"]
    verify: bool = True
    nmap: bool = False
    scan_mode: Optional[Literal["domains", "nmap", "combined"]] = None
    nmap_ports: Optional[str] = None
    nmap_profile: str = "fast"
    concurrency: int = Field(default=10, ge=1, le=50)

class NodePositionsRequest(BaseModel):
    positions: Dict[str, Dict[str, float]]

class NodeHideRequest(BaseModel):
    node_ids: List[str]

async def _run_scan_job(job_id: str, req: ScanRequest):
    try:
        scan_mode = req.scan_mode or ("combined" if req.nmap else "domains")
        nmap_enabled = scan_mode in {"nmap", "combined"}
        domain_lookup_enabled = scan_mode in {"domains", "combined"}
        JOBS.update(job_id, status="parsing_targets", progress_pct=5, stage="Анализ целевого ввода...")

        if not domain_lookup_enabled:
            if DomainReconEngine.is_domain_target(req.target):
                allowed, normalized = await validate_network_target(req.target)
                if not allowed:
                    raise ValueError(normalized)
                req.target = normalized
                resolved = await DomainVerifier.resolve_domain(req.target, timeout=5)
                ips = sorted(resolved)
                if not ips:
                    raise ValueError("Домен не удалось разрешить в IP-адрес")
                results = [{
                    "ip": ip, "domains": [req.target], "provider_details": {},
                    "candidate_domains": [req.target], "rejected_candidates": [],
                    "total_domains": 1, "verified_live": True,
                } for ip in ips]
            else:
                ips = list(IPParser.parse_target(req.target))
                if not ips:
                    raise ValueError("Не найден допустимый IP-адрес")
                results = [{
                    "ip": ip, "domains": [], "provider_details": {},
                    "candidate_domains": [], "rejected_candidates": [],
                    "total_domains": 0, "verified_live": False,
                } for ip in ips]
            if not private_targets_allowed() and any(not ipaddress.ip_address(ip).is_global for ip in ips):
                raise ValueError("Private, loopback, link-local and reserved targets are disabled")
            JOBS.update(job_id, total_ips=len(ips), progress_pct=60,
                        stage=f"Режим «Только Nmap» · подготовлено IP: {len(ips)}")

        elif DomainReconEngine.is_domain_target(req.target):
            allowed, normalized = await validate_network_target(req.target, allow_unresolved_domain=True)
            if not allowed:
                raise ValueError(normalized)
            req.target = normalized
            JOBS.update(job_id, status="domain_recon", progress_pct=10,
                        stage=f"Доменный поиск: поиск поддоменов для {req.target}...")

            def _on_recon_progress(pct: int, stage_name: str):
                base_pct = 10 + int(pct * 0.5) if nmap_enabled else 10 + int(pct * 0.8)
                prefix = "Этап 1/2 · Поиск доменов и связей · " if nmap_enabled else ""
                JOBS.update(job_id, progress_pct=base_pct, stage=prefix + stage_name)

            recon_engine = DomainReconEngine(concurrency=req.concurrency)
            results = await recon_engine.run_domain_recon(req.target, progress_callback=_on_recon_progress)
            ips = [r["ip"] for r in results]
        else:
            ips = list(IPParser.parse_target(req.target))
            if not ips:
                JOBS.update(job_id, status="error", progress_pct=0,
                            error="No valid IP addresses or domain name found in target input.")
                return
            if not private_targets_allowed() and any(not ipaddress.ip_address(ip).is_global for ip in ips):
                raise ValueError("Private, loopback, link-local and reserved targets are disabled")

            total_ips = len(ips)
            JOBS.update(job_id, total_ips=total_ips, status="running_lookups",
                        stage=f"Поиск доменов для {total_ips} IP...")

            def _on_lookup_progress(completed: int, total: int, stage_name: str, calculated_pct: int = None):
                if calculated_pct is not None:
                    pct = max(5, min(92, calculated_pct))
                else:
                    base_scale = 60 if nmap_enabled else 90
                    pct = 5 + int((completed / total) * base_scale)
                prefix = "Этап 1/2 · Поиск доменов и связей · " if nmap_enabled else ""
                JOBS.update(job_id, progress_pct=pct, stage=prefix + stage_name)

            provider_manager = ProviderManager(selected_providers=req.providers)
            engine = LookupEngine(
                provider_manager=provider_manager,
                concurrency=req.concurrency,
                verify_live=req.verify,
            )

            results = await engine.run(ips, progress_callback=_on_lookup_progress)

        if nmap_enabled:
            nmap_stage_prefix = "Этап 2/2 · Nmap" if domain_lookup_enabled else "Nmap"
            profile_hints = {
                "fast": "проверка 50 популярных портов",
                "normal": "проверка 200 популярных портов",
                "full": "проверка всех 65 535 TCP-портов; это может занять до 15 минут на IP",
                "stealth": "медленное SYN-сканирование 100 портов",
                "udp": "проверка 30 популярных UDP-портов",
            }
            nmap_hint = "проверка указанных портов" if req.nmap_ports else profile_hints.get(req.nmap_profile, "сканирование портов")
            JOBS.update(job_id, status="scanning_ports", progress_pct=65,
                        stage=f"{nmap_stage_prefix} ({req.nmap_profile}) · {nmap_hint} · запуск процесса...")
            scanner = NmapScanner(ports=req.nmap_ports, profile=req.nmap_profile)
            nmap_completed = 0
            nmap_activity = ""

            def _on_nmap_progress(completed: int, total: int, stage_name: str):
                nonlocal nmap_completed, nmap_activity
                nmap_completed = completed
                nmap_activity = stage_name
                pct = 65 + int((completed / total) * 30)
                JOBS.update(job_id, progress_pct=pct,
                            stage=f"{nmap_stage_prefix} · готово {completed}/{total} IP · {stage_name}")

            if scanner.is_available():
                nmap_ips = [ip for ip in ips if private_targets_allowed() or ipaddress.ip_address(ip).is_global]
                skipped_ips = set(ips) - set(nmap_ips)
                nmap_started = time.monotonic()
                scan_task = asyncio.create_task(scanner.scan_ips_concurrently(
                    nmap_ips, max_concurrency=min(req.concurrency, 4), progress_callback=_on_nmap_progress,
                    use_cache=False, return_details=True,
                ))
                while not scan_task.done():
                    done, _ = await asyncio.wait({scan_task}, timeout=2)
                    if done:
                        break
                    elapsed = int(time.monotonic() - nmap_started)
                    pct = 65 + int((nmap_completed / max(1, len(nmap_ips))) * 30)
                    JOBS.update(
                        job_id, progress_pct=pct,
                        stage=(f"{nmap_stage_prefix} ({req.nmap_profile}) работает · "
                               f"готово {nmap_completed}/{len(nmap_ips)} IP · прошло {elapsed} сек. · "
                               f"{nmap_activity or nmap_hint}"),
                    )
                port_map = await scan_task
                for item in results:
                    ip = item["ip"]
                    detail = port_map.get(ip, {})
                    item["open_ports"] = detail.get("open_ports", [])
                    item["nmap_status"] = "skipped" if ip in skipped_ips else ("error" if detail.get("error") else "completed")
                    item["nmap_error"] = "Приватный или служебный IP пропущен" if ip in skipped_ips else detail.get("error", "")
                    item["nmap_hostname"] = detail.get("hostname", "")
                    item["nmap_os"] = detail.get("os", "")
                    item["nmap_tech_stack"] = detail.get("tech_stack", [])
            else:
                for item in results:
                    item["nmap_status"] = "unavailable"
                    item["nmap_error"] = "Nmap не установлен на сервере"
                    item["nmap_tech_stack"] = []

        JOBS.update(job_id, status="building_graph", stage="Построение графа связей...", progress_pct=95)
        graph_data = GraphBuilder.build_graph(results, hide_empty_ips=scan_mode != "nmap")
        total_domains = sum(len(item.get("domains", [])) for item in results)

        JOBS.update(job_id,
            results=results,
            graph=graph_data,
            status="completed",
            progress_pct=100,
            stage="Сканирование завершено! (100%)",
        )

        storage.save_scan(
            job_id=job_id,
            target=req.target,
            verify=req.verify,
            nmap=nmap_enabled,
            total_ips=len(ips),
            total_domains=total_domains,
            results=results,
            graph=graph_data,
            status="completed",
        )
    except Exception as e:
        logger.error(f"Scan job {job_id} failed: {e}", exc_info=True)
        JOBS.update(job_id, status="error", error=str(e))

@router.get("/api/providers")
def get_providers():
    return {
        name: {"name": name, "description": cls.description}
        for name, cls in AVAILABLE_PROVIDERS.items()
    }

@router.get("/api/history")
def get_history():
    return storage.list_history()

@router.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_mode = req.scan_mode or ("combined" if req.nmap else "domains")
    nmap_enabled = scan_mode in {"nmap", "combined"}
    if nmap_enabled:
        try:
            NmapScanner.validate_ports(req.nmap_ports)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if req.nmap_profile not in SCAN_PROFILES:
            raise HTTPException(status_code=400, detail="Неизвестный профиль Nmap")
    terminal_statuses = {"completed", "error", "interrupted"}
    active_jobs = [(job_id, job) for job_id, job in JOBS.items()
                   if job.get("status") not in terminal_statuses]
    target_key = req.target.strip().lower().rstrip(".")
    for existing_id, existing in active_jobs:
        if str(existing.get("target", "")).strip().lower().rstrip(".") == target_key:
            return {
                "job_id": existing_id,
                "status": "already_running",
                "message": "Сканирование этой цели уже выполняется",
            }
    active_count = len(active_jobs)
    if active_count >= 4:
        raise HTTPException(status_code=429, detail="Too many active scan jobs")
    job_id = str(uuid.uuid4())[:8]
    JOBS.create(job_id, {
        "job_id": job_id,
        "status": "queued",
        "target": req.target,
        "verify": req.verify,
        "nmap": nmap_enabled,
        "scan_mode": scan_mode,
        "nmap_ports": req.nmap_ports,
        "nmap_profile": req.nmap_profile,
        "concurrency": req.concurrency,
        "total_ips": 0,
        "results": [],
        "graph": {"nodes": [], "edges": [], "stats": {}},
        "error": None,
    })
    background_tasks.add_task(_run_scan_job, job_id, req)
    return {"job_id": job_id, "status": "queued"}

@router.get("/api/scan/active")
def get_active_scans():
    terminal_statuses = {"completed", "error", "interrupted"}
    public_fields = (
        "job_id", "target", "status", "progress_pct", "stage", "verify", "nmap",
        "scan_mode", "nmap_ports", "nmap_profile", "concurrency", "total_ips", "error",
    )
    return {
        "jobs": [{field: job.get(field) for field in public_fields} for _, job in JOBS.items()
                 if job.get("status") not in terminal_statuses]
    }

@router.get("/api/graph/global")
def get_global_graph():
    global_results = storage.get_global_scan_results()
    graph_data = GraphBuilder.build_graph(global_results, hide_empty_ips=True)

    saved_positions = storage.get_all_node_positions()
    for node in graph_data.get("nodes", []):
        n_id = node["id"]
        if n_id in saved_positions:
            node["x"] = saved_positions[n_id]["x"]
            node["y"] = saved_positions[n_id]["y"]

    hidden_nodes = storage.get_hidden_nodes()

    return {
        "results": global_results,
        "graph": graph_data,
        "saved_positions": saved_positions,
        "hidden_node_ids": hidden_nodes,
    }

@router.post("/api/graph/positions")
def save_graph_node_positions(req: NodePositionsRequest):
    storage.save_node_positions(req.positions)
    return {"status": "saved", "count": len(req.positions)}

@router.get("/api/graph/nodes/hidden")
def get_hidden_nodes_api():
    return {"hidden_nodes": storage.get_hidden_nodes()}

@router.post("/api/graph/nodes/hide")
def hide_nodes_api(req: NodeHideRequest):
    storage.hide_nodes(req.node_ids)
    return {"status": "hidden", "count": len(req.node_ids)}

@router.post("/api/graph/nodes/unhide")
def unhide_nodes_api(req: NodeHideRequest):
    expanded_ids = set(req.node_ids)
    try:
        global_results = storage.get_global_scan_results()
        for nid in list(expanded_ids):
            if nid.startswith("ip:"):
                target_ip = nid.replace("ip:", "")
                for rec in global_results:
                    if rec.get("ip") == target_ip:
                        for d in rec.get("domains", []):
                            d_clean = decode_punycode(d.strip().lower())
                            if d_clean.startswith("www."):
                                d_clean = d_clean[4:]
                            apex = GraphBuilder.extract_apex_domain(d_clean)
                            expanded_ids.add(f"domain:{apex}")
                            if d_clean != apex:
                                expanded_ids.add(f"subdomain:{d_clean}")
    except Exception as e:
        logger.error(f"Failed expanding unhide node IDs: {e}")

    storage.unhide_nodes(list(expanded_ids))
    return {"status": "unhidden", "count": len(expanded_ids)}

@router.post("/api/graph/nodes/unhide-all")
def unhide_all_nodes_api():
    storage.clear_hidden_nodes()
    return {"status": "cleared"}

@router.get("/api/scan/{job_id}")
def get_scan_status(job_id: str):
    hidden_nodes = storage.get_hidden_nodes()
    job = JOBS.get(job_id) if job_id in JOBS else None
    if job:
        res = dict(job)
        res["hidden_node_ids"] = hidden_nodes
        return res

    saved_scan = storage.get_scan(job_id)
    if saved_scan:
        res = dict(saved_scan)
        res["hidden_node_ids"] = hidden_nodes
        return res

    persisted_job = JOBS.get(job_id)
    if persisted_job:
        return persisted_job

    raise HTTPException(status_code=404, detail="Job not found")

@router.get("/api/graph/{job_id}")
def get_scan_graph(job_id: str):
    job = JOBS.get(job_id) if job_id in JOBS else None
    if job:
        return job.get("graph", {"nodes": [], "edges": [], "stats": {}})

    saved_scan = storage.get_scan(job_id)
    if saved_scan:
        return saved_scan.get("graph", {"nodes": [], "edges": [], "stats": {}})

    raise HTTPException(status_code=404, detail="Job not found")

@router.delete("/api/history/{job_id}")
def delete_scan_history(job_id: str):
    storage.delete_scan(job_id)
    if job_id in JOBS:
        del JOBS[job_id]
    return {"status": "deleted", "job_id": job_id}
