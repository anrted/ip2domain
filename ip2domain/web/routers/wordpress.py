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


class WPScanRequest(BaseModel):
    targets: List[str] = Field(..., min_items=1, max_items=10000)
    ports: Optional[List[int]] = Field(default_factory=lambda: [80, 443])
    concurrency: int = Field(default=150, ge=10, le=500)
    deep_scan: bool = Field(default=True)


async def _run_wp_hunter_job(job_id: str, raw_targets: List[str], ports: List[int], concurrency: int, deep_scan: bool):
    try:
        hunter = WPHunter(concurrency=concurrency, deep_scan=deep_scan)
        parsed_targets = hunter.parse_targets(raw_targets, ports=ports)
        total_targets = len(parsed_targets)

        if total_targets == 0:
            WP_JOBS[job_id]["status"] = "completed"
            WP_JOBS[job_id]["progress_pct"] = 100
            WP_JOBS[job_id]["stage"] = "Нет доступных целей для сканирования"
            storage.update_wp_job(job_id, status="completed", completed_targets=0, found_wp=0, finished=True)
            return

        WP_JOBS[job_id]["total_targets"] = total_targets
        WP_JOBS[job_id]["status"] = "running"
        WP_JOBS[job_id]["stage"] = f"Сканирование {total_targets} целей..."
        storage.update_wp_job(job_id, status="running", completed_targets=0)

        found_wp_count = 0
        batch_results: List[Dict[str, Any]] = []

        def _on_progress(completed: int, total: int, res: Dict[str, Any]):
            nonlocal found_wp_count
            if STOP_FLAGS.get(job_id):
                return
            if res.get("is_wordpress"):
                found_wp_count += 1
                batch_results.append(res)
            pct = int((completed / total) * 100)
            WP_JOBS[job_id].update(
                progress_pct=pct,
                completed_targets=completed,
                found_wp=found_wp_count,
                stage=f"Проверено {completed}/{total} · Найдено WordPress: {found_wp_count}",
            )
            # Periodic flush to SQLite every 25 findings
            if len(batch_results) >= 25:
                to_save = list(batch_results)
                batch_results.clear()
                storage.save_wp_results_batch(job_id, to_save)
                storage.update_wp_job(job_id, completed_targets=completed, found_wp=found_wp_count)

        # Execute scan
        results = await hunter.scan_targets(parsed_targets, progress_callback=_on_progress)

        if batch_results:
            storage.save_wp_results_batch(job_id, batch_results)
            batch_results.clear()

        # If any findings weren't captured in the stream batch, flush all
        all_wp = [r for r in results if r.get("is_wordpress")]
        found_wp_count = len(all_wp)

        WP_JOBS[job_id].update(
            status="completed",
            progress_pct=100,
            completed_targets=len(results),
            found_wp=found_wp_count,
            stage=f"Завершено. Проверено {len(results)} · Найдено WordPress: {found_wp_count}",
        )
        storage.update_wp_job(
            job_id, status="completed", completed_targets=len(results), found_wp=found_wp_count, finished=True
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
    if job_id in WP_JOBS:
        STOP_FLAGS[job_id] = True
        WP_JOBS[job_id]["status"] = "stopped"
        WP_JOBS[job_id]["stage"] = "Остановлено пользователем"
        storage.update_wp_job(job_id, status="stopped", finished=True)
        return {"status": "stopped", "job_id": job_id}
    raise HTTPException(status_code=404, detail="Активная задача не найдена")


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
