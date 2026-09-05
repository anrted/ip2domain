import asyncio
import logging
import os
import shutil
import time
from typing import List

from ip2domain.cameras.centra_engine.screens import _prepare_centra_person_frame
from ip2domain.web.routers.common import (
    storage,
    CENTRA_PERSON_JOBS,
    CENTRA_PERSON_MODEL,
)

logger = logging.getLogger(__name__)


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
