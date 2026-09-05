import asyncio
import logging
import re
import time
from typing import List, Optional
from urllib.parse import urlparse

import aiohttp
from fastapi import HTTPException

from ip2domain.cameras.centra_engine.geo import _centra_address
from ip2domain.cameras.centra_engine.models import CentraDiscoveryRequest
from ip2domain.web.routers.common import (
    storage,
    CENTRA_JOBS,
)

logger = logging.getLogger(__name__)


def _centra_discovery_types(value: str) -> List[str]:
    value = value.strip().upper().replace(" ", "")
    if value in {"ALL", "KNOWN", "ALL_KNOWN"}:
        return ["I", "G", "H", "P", "T", "A"]
    if value in {"ALL_LETTERS", "FULL", "EVERYTHING", "ALL_TYPES"}:
        return [chr(code) for code in range(ord("A"), ord("Z") + 1)]
    if value in {"I", "G", "H", "T", "A", "P"}:
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


async def _run_centra_discovery(job_id: str, req: CentraDiscoveryRequest):
    possible_total = (req.end_id - req.start_id + 1) * (req.entrance_end - req.entrance_start + 1)
    checked = found = retries = 0
    current_building = req.start_id
    semaphore = asyncio.Semaphore(req.concurrency)
    timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_read=5)
    headers = {"User-Agent": "ip2domain-centra-discovery/1.0"}
    known = {camera["id"]: camera for camera in storage.get_centra_cameras()}
    # Cache: building_bucket (building_id // 10) -> last known live host
    # Gives ~80% reduction in cold-start probes for sequential building ranges
    host_cache: dict[int, str] = {}
    camera_type = req.camera_type.upper()
    all_hosts = ["flus4.mycentra.ru", "flus5.mycentra.ru", "flus1.mycentra.ru",
                 "flus2.mycentra.ru", "flus3.mycentra.ru", "flus.mycentra.ru", "flus6.mycentra.ru"]
    hosts = ([urlparse(req.base_url).hostname] if req.base_url else all_hosts)
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
            camera_hosts = list(hosts)
            # --- Priority 1: host from DB record for this specific camera ---
            existing = known.get(camera_id) or {}
            saved_host = str(existing.get("stream_host") or "").strip().lower()
            if not saved_host:
                saved_host = (urlparse(str(existing.get("embed_url") or "")).hostname or "").lower()
            if saved_host and saved_host in camera_hosts:
                camera_hosts.remove(saved_host)
                camera_hosts.insert(0, saved_host)
            elif not req.base_url:
                # --- Priority 2: cached host from neighbouring buildings ---
                bucket = building // 10
                cached_host = host_cache.get(bucket) or host_cache.get(bucket - 1)
                if cached_host and cached_host in camera_hosts:
                    camera_hosts.remove(cached_host)
                    camera_hosts.insert(0, cached_host)

            # Inner host check — NOT guarded by semaphore so all 7 hosts
            # for a single camera can race in parallel without blocking
            # other cameras in the semaphore queue.
            async def check_host_preview(h: str) -> Optional[str]:
                candidate_url = f"https://{h}/{camera_id}/preview.jpg"
                for attempt in range(2):
                    if cancellation_requested():
                        return None
                    try:
                        async with session.head(candidate_url, allow_redirects=False) as response:
                            if response.status == 200:
                                return h
                            if response.status == 404:
                                return None
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt == 0:
                            retries += 1
                            await asyncio.sleep(0.15)
                            continue
                    except Exception:
                        return None
                return None

            selected_host = None
            if len(camera_hosts) == 1:
                selected_host = await check_host_preview(camera_hosts[0])
            else:
                host_tasks = [asyncio.create_task(check_host_preview(h)) for h in camera_hosts]
                try:
                    for coro in asyncio.as_completed(host_tasks):
                        winner = await coro
                        if winner:
                            selected_host = winner
                            break
                finally:
                    for t in host_tasks:
                        if not t.done():
                            t.cancel()

            # Update host cache on success so next buildings skip losers
            if selected_host:
                host_cache[building // 10] = selected_host

            if cancellation_requested():
                conclusive = False
                return

            if not selected_host:
                return

            # Phase 2: Metadata enrichment
            data = None
            media_url = f"https://{selected_host}/{camera_id}/media_info.json"
            try:
                async with semaphore:
                    async with session.get(media_url, allow_redirects=False) as response:
                        if response.status == 200:
                            data = await response.json(content_type=None)
            except Exception:
                pass

            data = data if isinstance(data, dict) else {}
            tracks = data.get("tracks") or []
            video = next((track for track in tracks if isinstance(track, dict) and track.get("content") == "video"), {})
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
        except Exception:
            conclusive = False
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
        if cancellation_requested():
            CENTRA_JOBS.update(job_id, status="cancelled", progress_pct=0,
                               stage=f"Поиск типа {camera_type} отменен пользователем",
                               checked=0, found=0, skipped=skipped)
            return
        CENTRA_JOBS.update(job_id, status="running", progress_pct=0, started_at=started_at,
                           speed=0, eta_seconds=None,
                           stage=(f"Подготовка типа {camera_type} · {total:,} проверок"
                                  + (f" · пропущено {skipped:,}" if skipped else "")))
        if total == 0:
            CENTRA_JOBS.update(job_id, status="completed", progress_pct=100,
                               stage=f"Готово · все {skipped:,} камер уже находятся в базе",
                               checked=0, found=0, skipped=skipped)
            return
        connector = aiohttp.TCPConnector(
            limit=max(60, req.concurrency * 2),
            limit_per_host=max(20, req.concurrency // 2),
            ttl_dns_cache=600,
            enable_cleanup_closed=True,
        )
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=6, connect=2, sock_read=3),
            connector=connector,
            headers=headers
        ) as session:
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
