"""
FastAPI router for WordPress Hunter module.
Handles mass discovery tasks, status polling, results querying, export, and topology import.
"""

import asyncio
import csv
import io
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ip2domain.modules.wp_hunter import WPHunter
from ip2domain.web.routers.common import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/wp", tags=["WordPress Hunter"])

# In-memory registry of active jobs: job_id -> dict
WP_JOBS: Dict[str, Dict[str, Any]] = {}
STOP_FLAGS: Dict[str, bool] = {}

# Clean up dangling jobs from previous server runs
try:
    storage.stop_all_wp_jobs()
except Exception as _e:
    logger.debug("Failed to cleanup dangling wp jobs on load: %s", _e)


class WPScanRequest(BaseModel):
    targets: List[str] = Field(..., min_items=1, max_items=10000)
    ports: Optional[List[int]] = Field(default_factory=lambda: [80, 443])
    concurrency: int = Field(default=150, ge=10, le=500)
    deep_scan: bool = Field(default=True)


async def _run_wp_hunter_job(job_id: str, raw_targets: List[str], ports: List[int], concurrency: int, deep_scan: bool):
    try:
        hunter = WPHunter(concurrency=concurrency, deep_scan=deep_scan)

        # 1. Partition targets: direct domains vs IP/CIDR specs
        direct_targets, ip_specs, total_ips = hunter.partition_targets(raw_targets, ports=ports)

        # Immediately save direct domains to disk without keeping in RAM
        if direct_targets:
            storage.save_wp_job_targets_batch(job_id, direct_targets)

        WP_JOBS[job_id]["status"] = "running"

        # --- ФАЗА 1: Определение доменов по IP (SSL SAN / PTR) ---
        if ip_specs and total_ips > 0:
            WP_JOBS[job_id]["stage"] = f"Фаза 1/2: Поиск доменов по IP (SSL SAN)... (0/{total_ips:,})".replace(",", " ")

            def _on_domain_batch(batch: List[Dict[str, Any]]):
                if batch:
                    storage.save_wp_job_targets_batch(job_id, batch)

            def _on_discovery_progress(completed: int, total: int, discovered: int):
                if STOP_FLAGS.get(job_id):
                    return
                # Phase 1 maps to 0% - 50%
                pct = int((completed / total) * 50) if total else 0
                stage_text = (
                    f"Фаза 1/2: Поиск доменов по IP... Найдено доменов: {discovered:,} · Проверено IP: {completed:,}/{total:,}"
                ).replace(",", " ")
                WP_JOBS[job_id].update(
                    progress_pct=min(50, pct),
                    completed_targets=completed,
                    stage=stage_text,
                )
                storage.update_wp_job(job_id, completed_targets=completed)

            ip_generator = hunter.iter_ips_from_specs(ip_specs)
            await hunter.discover_domains_phase(
                ip_stream=ip_generator,
                ports=ports,
                total_ips=total_ips,
                on_batch_found=_on_domain_batch,
                progress_callback=_on_discovery_progress,
                stop_check=lambda: STOP_FLAGS.get(job_id, False),
            )

        if STOP_FLAGS.get(job_id):
            WP_JOBS[job_id]["stage"] = "Остановлено пользователем"
            WP_JOBS[job_id]["status"] = "stopped"
            storage.update_wp_job(job_id, status="stopped", finished=True)
            return

        # --- ФАЗА 2: Сканирование WordPress на всех найденных доменах ---
        total_targets_to_scan = storage.count_wp_job_targets(job_id, status="pending")
        if total_targets_to_scan == 0:
            WP_JOBS[job_id].update(
                status="completed",
                progress_pct=100,
                stage="Завершено. Активных веб-хостов или доменов не обнаружено.",
            )
            storage.update_wp_job(job_id, status="completed", finished=True)
            return

        WP_JOBS[job_id]["total_targets"] = total_targets_to_scan
        WP_JOBS[job_id]["stage"] = (
            f"Фаза 2/2: Сканирование WordPress на {total_targets_to_scan:,} доменах...".replace(",", " ")
        )

        found_wp_hosts: Set[str] = set()
        batch_results: List[Dict[str, Any]] = []
        completed_sites = 0

        # Stream pending targets directly from SQLite in chunks of 200 without RAM bloat
        async def pending_targets_stream():
            while True:
                if STOP_FLAGS.get(job_id):
                    break
                chunk = storage.get_pending_wp_job_targets(job_id, limit=200)
                if not chunk:
                    break
                storage.mark_wp_job_targets_scanned([c["id"] for c in chunk])
                for item in chunk:
                    yield item

        def _on_scan_progress(completed: int, total: int, res: Dict[str, Any]):
            nonlocal completed_sites
            if STOP_FLAGS.get(job_id):
                return
            completed_sites = completed
            if res.get("is_wordpress"):
                found_wp_hosts.add(str(res.get("host") or "").strip().lower())
                batch_results.append(res)

            found_count = len(found_wp_hosts)
            # Phase 2 maps to 50% - 100%
            pct = 50 + int((completed / total) * 50) if total else 50
            stage_text = (
                f"Фаза 2/2: Сканирование WordPress... Проверено {completed:,}/{total:,} · Найдено сайтов: {found_count}"
            ).replace(",", " ")
            WP_JOBS[job_id].update(
                progress_pct=min(100, pct),
                completed_targets=completed,
                found_wp=found_count,
                stage=stage_text,
            )
            if len(batch_results) >= 20:
                to_save = list(batch_results)
                batch_results.clear()
                storage.save_wp_results_batch(job_id, to_save)
                storage.update_wp_job(job_id, completed_targets=completed, found_wp=found_count)

        await hunter.scan_targets(
            targets=pending_targets_stream(),
            total_count=total_targets_to_scan,
            progress_callback=_on_scan_progress,
            stop_check=lambda: STOP_FLAGS.get(job_id, False),
        )

        if batch_results:
            storage.save_wp_results_batch(job_id, batch_results)
            batch_results.clear()

        is_stopped = STOP_FLAGS.get(job_id, False)
        final_status = "stopped" if is_stopped else "completed"
        final_completed = completed_sites or total_targets_to_scan
        final_found_count = len(found_wp_hosts)

        WP_JOBS[job_id].update(
            status=final_status,
            progress_pct=100 if final_status == "completed" else WP_JOBS[job_id].get("progress_pct", 0),
            completed_targets=final_completed,
            found_wp=final_found_count,
            stage=f"Завершено. Проверено {final_completed:,} сайтов · Найдено WordPress: {final_found_count}".replace(",", " ")
            if final_status == "completed"
            else "Остановлено пользователем",
        )
        storage.update_wp_job(
            job_id,
            status=final_status,
            completed_targets=final_completed,
            found_wp=final_found_count,
            finished=True,
        )

    except Exception as exc:
        logger.error(f"[WPHunter] Job {job_id} failed: {exc}", exc_info=True)
        WP_JOBS[job_id].update(status="error", error=str(exc), stage="Ошибка сканирования")
        storage.update_wp_job(job_id, status="error", finished=True)


@router.post("/scan")
async def start_wp_scan(req: WPScanRequest, background_tasks: BackgroundTasks):
    active_jobs = sum(1 for _, j in WP_JOBS.items() if j.get("status") in ("queued", "running"))
    if active_jobs >= 3:
        raise HTTPException(status_code=429, detail="Слишком много активных задач сканирования WordPress (макс 3)")

    job_id = str(uuid.uuid4())[:8]
    raw_targets = [t.strip() for t in req.targets if t.strip()]
    target_preview = ", ".join(raw_targets[:3])
    if len(raw_targets) > 3:
        target_preview += f" (+ещё {len(raw_targets) - 3})"

    job_info = {
        "job_id": job_id,
        "target_input": target_preview,
        "ports": req.ports or [80, 443],
        "concurrency": req.concurrency,
        "deep_scan": req.deep_scan,
        "status": "queued",
        "progress_pct": 0,
        "total_targets": len(raw_targets),
        "completed_targets": 0,
        "found_wp": 0,
        "stage": "Инициализация сканера...",
        "error": None,
    }
    WP_JOBS[job_id] = job_info
    STOP_FLAGS[job_id] = False
    storage.create_wp_job(job_id, target_preview, req.ports or [80, 443], len(raw_targets))

    background_tasks.add_task(
        _run_wp_hunter_job, job_id, raw_targets, req.ports or [80, 443], req.concurrency, req.deep_scan
    )
    return {"status": "queued", "job_id": job_id, "message": "Сканирование WordPress запущено"}


@router.get("/jobs")
def get_wp_jobs():
    recent = storage.get_recent_wp_jobs(limit=15)
    # Merge with memory state for active jobs
    for item in recent:
        j_id = item["id"]
        if j_id in WP_JOBS:
            item.update(WP_JOBS[j_id])
    return recent


@router.get("/job/{job_id}")
def get_wp_job_status(job_id: str):
    if job_id in WP_JOBS:
        return WP_JOBS[job_id]
    job = storage.get_wp_job(job_id)
    if job:
        return job
    raise HTTPException(status_code=404, detail="Задача сканирования не найдена")


@router.post("/job/{job_id}/stop")
def stop_wp_job(job_id: str):
    STOP_FLAGS[job_id] = True
    if job_id in WP_JOBS:
        WP_JOBS[job_id]["status"] = "stopped"
        WP_JOBS[job_id]["stage"] = "Остановлено пользователем"

    # Always persist stop in database as well (handles cases after server restart)
    job = storage.get_wp_job(job_id)
    if job:
        storage.update_wp_job(job_id, status="stopped", finished=True)
        return {"status": "stopped", "job_id": job_id}

    if job_id in WP_JOBS:
        return {"status": "stopped", "job_id": job_id}

    return {"status": "stopped", "job_id": job_id, "note": "Job was already completed or not found"}


@router.post("/jobs/stop-all")
def stop_all_wp_jobs():
    for j_id in list(WP_JOBS.keys()):
        STOP_FLAGS[j_id] = True
        WP_JOBS[j_id]["status"] = "stopped"
        WP_JOBS[j_id]["stage"] = "Остановлено пользователем"
        storage.update_wp_job(j_id, status="stopped", finished=True)
    storage.stop_all_wp_jobs()
    return {"status": "all_stopped"}


@router.get("/results")
def get_wp_results(
    job_id: Optional[str] = None,
    only_wp: bool = True,
    version: Optional[str] = None,
    plugin: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return storage.get_wp_results(
        job_id=job_id,
        only_wp=only_wp,
        version=version,
        plugin=plugin,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get("/stats")
def get_wp_stats():
    return storage.get_wp_stats()


@router.post("/import_topology")
def import_topology_targets():
    """Extract all previously discovered web nodes (port 80/443/etc.) from topology."""
    discovered: List[Dict[str, Any]] = []
    seen = set()
    if hasattr(storage, "get_global_scan_results"):
        for item in storage.get_global_scan_results():
            ip = item.get("ip", "").strip()
            domains = item.get("domains", []) or []
            ports = item.get("ports", []) or []

            web_ports = []
            for p in ports:
                p_num = p.get("port") if isinstance(p, dict) else p
                if p_num in (80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000):
                    web_ports.append(p_num)

            # Add domains or IP
            for dom in domains:
                d_clean = dom.strip().lower()
                if d_clean and d_clean not in seen:
                    seen.add(d_clean)
                    discovered.append({"target": d_clean, "type": "domain", "ports": web_ports or [80, 443]})

            if not domains and ip and ip not in seen:
                seen.add(ip)
                discovered.append({"target": ip, "type": "ip", "ports": web_ports or [80, 443]})

    return {
        "total": len(discovered),
        "targets": [d["target"] for d in discovered],
        "items": discovered[:500],
    }


@router.get("/export")
def export_wp_results(
    format: str = Query(default="csv", regex="^(csv|json)$"),
    job_id: Optional[str] = None,
    only_wp: bool = True,
):
    data = storage.get_wp_results(job_id=job_id, only_wp=only_wp, limit=10000, offset=0)
    items = data.get("items", [])

    if format == "json":
        content = json.dumps(items, ensure_ascii=False, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=wordpress_hunter_results.json"},
        )

    # CSV export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "URL", "Host", "Port", "Scheme", "Status", "Is WordPress",
        "Version", "Version Source", "Theme", "Plugins", "Title", "Server", "Latency (ms)"
    ])
    for item in items:
        writer.writerow([
            item.get("url"),
            item.get("host"),
            item.get("port"),
            item.get("scheme"),
            item.get("status_code"),
            item.get("is_wordpress"),
            item.get("version") or "Не определена",
            item.get("version_source") or "",
            item.get("theme") or "",
            ", ".join(item.get("plugins") or []),
            item.get("title") or "",
            item.get("server") or "",
            item.get("latency_ms") or 0,
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=wordpress_hunter_results.csv"},
    )


@router.delete("/results")
def clear_wp_results(job_id: Optional[str] = None):
    storage.clear_wp_results(job_id=job_id)
    if job_id and job_id in WP_JOBS:
        WP_JOBS.pop(job_id, None)
    elif not job_id:
        WP_JOBS.clear()
    return {"status": "cleared", "message": "Результаты успешно удалены"}
