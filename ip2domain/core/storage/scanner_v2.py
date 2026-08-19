"""Camera Scanner v2 — SQLite storage mixin."""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ScannerV2StorageMixin:
    """Adds v2_results and v2_jobs tables to the StorageManager."""

    def _init_v2_tables(self):
        """Initialize v2 scanner tables (called from BaseStorage._init_db)."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS v2_results (
                    ip          TEXT PRIMARY KEY,
                    brand       TEXT DEFAULT '',
                    model       TEXT DEFAULT '',
                    serial      TEXT DEFAULT '',
                    protocols   TEXT DEFAULT '[]',
                    streams_json TEXT NOT NULL DEFAULT '[]',
                    result_json TEXT NOT NULL,
                    is_garbage  INTEGER DEFAULT 0,
                    in_go2rtc   INTEGER DEFAULT 0,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_brand
                ON v2_results(brand, updated_at DESC)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS v2_jobs (
                    job_id      TEXT PRIMARY KEY,
                    status      TEXT NOT NULL DEFAULT 'queued',
                    targets_str TEXT DEFAULT '',
                    current_index INTEGER DEFAULT 0,
                    params_json TEXT NOT NULL DEFAULT '{}',
                    total_targets INTEGER DEFAULT 0,
                    found_cameras INTEGER DEFAULT 0,
                    engine_used TEXT DEFAULT '',
                    progress_pct INTEGER DEFAULT 0,
                    stage       TEXT DEFAULT '',
                    logs_json   TEXT DEFAULT '[]',
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Auto-migrate table if created with earlier schema
            cols = [r[1] for r in conn.execute("PRAGMA table_info(v2_jobs)").fetchall()]
            if "current_index" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN current_index INTEGER DEFAULT 0")
                except Exception:
                    pass
            if "targets_str" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN targets_str TEXT DEFAULT ''")
                except Exception:
                    pass
            conn.commit()

    def save_v2_result(self, result: Dict) -> None:
        """Upsert a single camera result from v2 scanner."""
        ip = str(result.get("ip", "")).strip()
        if not ip:
            return
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO v2_results (ip, brand, model, serial, protocols, streams_json, result_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    brand = excluded.brand,
                    model = excluded.model,
                    serial = excluded.serial,
                    protocols = excluded.protocols,
                    streams_json = excluded.streams_json,
                    result_json = excluded.result_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    ip,
                    str(result.get("brand", "")),
                    str(result.get("model", "")),
                    str(result.get("serial", "")),
                    json.dumps(result.get("protocols", []), ensure_ascii=False),
                    json.dumps(result.get("streams", []), ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False),
                ),
            )

    def _sync_from_strix_if_needed(self, conn) -> None:
        """If v2_results is empty, import existing discovered cameras from strix_results."""
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM v2_results").fetchone()[0]
            if cnt > 0:
                return
            strix_tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='strix_results'"
            ).fetchall()
            if not strix_tables:
                return
            strix_rows = conn.execute(
                "SELECT * FROM strix_results WHERE is_garbage = 0"
            ).fetchall()
            for r in strix_rows:
                ip = r["ip"]
                probe = json.loads(r["probe_json"] or "{}") if "probe_json" in r.keys() else {}
                streams_raw = json.loads(r["streams_json"] or "[]") if "streams_json" in r.keys() else []
                if not streams_raw:
                    continue
                brand = probe.get("brand") or probe.get("vendor") or ""
                model = probe.get("model") or ""
                streams = []
                for s in streams_raw:
                    url = s.get("source") or s.get("url") or ""
                    if url:
                        streams.append({
                            "url": url,
                            "type": "rtsp" if "rtsp://" in url else ("hls" if ".m3u8" in url else "http_snapshot"),
                            "verified": bool(s.get("screenshot") or s.get("codecs")),
                            "screenshot_path": s.get("screenshot") or "",
                            "codec": (s.get("codecs") or [""])[0] if isinstance(s.get("codecs"), list) else "",
                            "resolution": f"{s.get('width', '')}x{s.get('height', '')}" if s.get("width") else "",
                        })
                if not streams:
                    continue
                if not brand:
                    for s in streams:
                        if "Streaming/Channels" in s["url"]:
                            brand = "Hikvision"
                            break
                        elif "cam/realmonitor" in s["url"]:
                            brand = "Dahua"
                            break
                        elif "axis" in s["url"]:
                            brand = "Axis"
                            break
                    if not brand:
                        brand = "Generic Camera"
                cam_dict = {
                    "ip": ip,
                    "brand": brand,
                    "model": model,
                    "protocols": ["rtsp_direct"] if any(s["type"] == "rtsp" for s in streams) else ["http_snapshot"],
                    "streams": streams,
                    "open_ports": [554] if any(s["type"] == "rtsp" for s in streams) else [80],
                    "in_go2rtc": False,
                }
                conn.execute(
                    """
                    INSERT INTO v2_results (ip, brand, model, serial, protocols, streams_json, result_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(ip) DO NOTHING
                    """,
                    (
                        ip,
                        brand,
                        model,
                        "",
                        json.dumps(cam_dict["protocols"], ensure_ascii=False),
                        json.dumps(cam_dict["streams"], ensure_ascii=False),
                        json.dumps(cam_dict, ensure_ascii=False),
                    ),
                )
            conn.commit()
        except Exception as exc:
            logger.debug("[v2 Storage] Error syncing from strix: %s", exc)

    def get_v2_results(self, limit: int = 1000, brand: str = "", protocol: str = "") -> List[Dict]:
        """Retrieve v2 scanner results, optionally filtered."""
        with self._get_connection() as conn:
            self._sync_from_strix_if_needed(conn)
            query = "SELECT result_json, in_go2rtc FROM v2_results WHERE is_garbage = 0"
            params = []
            if brand:
                query += " AND brand LIKE ?"
                params.append(f"%{brand}%")
            if protocol:
                query += " AND protocols LIKE ?"
                params.append(f"%{protocol}%")
            query += " ORDER BY updated_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                try:
                    r = json.loads(row["result_json"])
                    r["in_go2rtc"] = bool(row["in_go2rtc"])
                    results.append(r)
                except Exception:
                    pass
            return results


    def get_v2_result(self, ip: str) -> Optional[Dict]:
        """Get a single v2 result by IP."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT result_json, in_go2rtc FROM v2_results WHERE ip = ?", (ip,)
            ).fetchone()
            if not row:
                return None
            try:
                r = json.loads(row["result_json"])
                r["in_go2rtc"] = bool(row["in_go2rtc"])
                return r
            except Exception:
                return None

    def clear_v2_results(self) -> None:
        """Delete all v2 results."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM v2_results")

    def delete_v2_result(self, ip: str) -> None:
        """Delete a single v2 result by IP."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM v2_results WHERE ip = ?", (ip,))

    def mark_v2_result_go2rtc(self, ip: str, in_go2rtc: bool) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_results SET in_go2rtc = ? WHERE ip = ?",
                (1 if in_go2rtc else 0, ip),
            )

    def set_v2_garbage(self, ip: str, is_garbage: bool) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_results SET is_garbage = ? WHERE ip = ?",
                (1 if is_garbage else 0, ip),
            )

    def get_v2_stats(self) -> Dict:
        """Return protocol and brand statistics for v2 results."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM v2_results WHERE is_garbage=0").fetchone()[0]
            by_brand = {}
            for row in conn.execute(
                "SELECT brand, COUNT(*) as cnt FROM v2_results WHERE is_garbage=0 GROUP BY brand ORDER BY cnt DESC"
            ).fetchall():
                by_brand[row["brand"] or "Unknown"] = row["cnt"]
            return {"total": total, "by_brand": by_brand}

    # ── Job Persistence & Auto-Resume ─────────────────────────────────────────

    def save_v2_job(self, job_dict: Dict) -> None:
        """Create or update a scan job record in SQLite."""
        job_id = job_dict.get("job_id", "")
        if not job_id:
            return
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO v2_jobs (job_id, status, targets_str, current_index, params_json,
                                     total_targets, found_cameras, engine_used, progress_pct, stage, logs_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    targets_str = CASE WHEN excluded.targets_str != '' THEN excluded.targets_str ELSE targets_str END,
                    current_index = excluded.current_index,
                    params_json = CASE WHEN excluded.params_json != '{}' THEN excluded.params_json ELSE params_json END,
                    total_targets = excluded.total_targets,
                    found_cameras = excluded.found_cameras,
                    engine_used = excluded.engine_used,
                    progress_pct = excluded.progress_pct,
                    stage = excluded.stage,
                    logs_json = excluded.logs_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    job_id,
                    job_dict.get("status", "queued"),
                    job_dict.get("targets_str", ""),
                    job_dict.get("current_index", 0),
                    json.dumps(job_dict.get("params", {}), ensure_ascii=False),
                    job_dict.get("total_targets", 0),
                    job_dict.get("results_count", len(job_dict.get("results", []))),
                    job_dict.get("engine_used", ""),
                    job_dict.get("progress_pct", 0),
                    job_dict.get("stage", ""),
                    json.dumps(job_dict.get("logs", []), ensure_ascii=False),
                ),
            )

    def update_v2_job_progress(
        self,
        job_id: str,
        current_index: int,
        progress_pct: int,
        stage: str,
        found_cameras: int,
        logs: Optional[List[str]] = None,
    ) -> None:
        """Lightweight update for scan progress and current target index."""
        with self._get_connection() as conn:
            if logs is not None:
                conn.execute(
                    """
                    UPDATE v2_jobs SET
                        current_index = ?,
                        progress_pct = ?,
                        stage = ?,
                        found_cameras = ?,
                        logs_json = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, progress_pct, stage, found_cameras, json.dumps(logs[-30:], ensure_ascii=False), job_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE v2_jobs SET
                        current_index = ?,
                        progress_pct = ?,
                        stage = ?,
                        found_cameras = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, progress_pct, stage, found_cameras, job_id),
                )

    def get_active_v2_job(self) -> Optional[Dict]:
        """Return the latest active/unfinished v2 scan job (status: queued or running)."""
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT job_id, status, targets_str, current_index, params_json, total_targets,
                       found_cameras, engine_used, progress_pct, stage, logs_json, created_at, updated_at
                FROM v2_jobs
                WHERE status IN ('running', 'queued')
                ORDER BY created_at DESC LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "targets_str": row["targets_str"] or "",
                "current_index": row["current_index"] or 0,
                "params": json.loads(row["params_json"] or "{}"),
                "total_targets": row["total_targets"] or 0,
                "found_cameras": row["found_cameras"] or 0,
                "engine_used": row["engine_used"] or "",
                "progress_pct": row["progress_pct"] or 0,
                "stage": row["stage"] or "",
                "logs": json.loads(row["logs_json"] or "[]"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def get_v2_job(self, job_id: str) -> Optional[Dict]:
        """Get job record by job_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT job_id, status, targets_str, current_index, params_json, total_targets,
                       found_cameras, engine_used, progress_pct, stage, logs_json, created_at, updated_at
                FROM v2_jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "targets_str": row["targets_str"] or "",
                "current_index": row["current_index"] or 0,
                "params": json.loads(row["params_json"] or "{}"),
                "total_targets": row["total_targets"] or 0,
                "found_cameras": row["found_cameras"] or 0,
                "engine_used": row["engine_used"] or "",
                "progress_pct": row["progress_pct"] or 0,
                "stage": row["stage"] or "",
                "logs": json.loads(row["logs_json"] or "[]"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def mark_v2_job_status(self, job_id: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_jobs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE job_id = ?",
                (status, job_id),
            )
