"""Strix video stream scanning results and persistent resume job checkpoints mixin."""
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class StrixStorageMixin:
    def save_strix_result(self, ip: str, session_id: str, probe: dict, streams: list, overwrite: bool = False):
        """Save or update discovered Strix streams for an IP in SQLite.
        
        If overwrite is True (e.g. strict video validation rescan), replaces previous streams with verified ones.
        """
        with self._get_connection() as conn:
            cur = conn.execute("SELECT session_id, probe_json, streams_json FROM strix_results WHERE ip = ?", (str(ip).strip(),))
            row = cur.fetchone()
            merged_streams = list(streams or [])
            if not overwrite and row and row["streams_json"]:
                try:
                    existing_streams = json.loads(row["streams_json"])
                    existing_sources = {st.get("source") for st in existing_streams if isinstance(st, dict) and st.get("source")}
                    for new_st in merged_streams:
                        if isinstance(new_st, dict) and new_st.get("source") not in existing_sources:
                            existing_streams.append(new_st)
                            existing_sources.add(new_st.get("source"))
                    merged_streams = existing_streams
                except Exception:
                    pass

            conn.execute(
                """
                INSERT INTO strix_results (ip, session_id, probe_json, streams_json, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    session_id = excluded.session_id,
                    probe_json = excluded.probe_json,
                    streams_json = excluded.streams_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    str(ip).strip(),
                    str(session_id or "").strip(),
                    json.dumps(probe or {}, ensure_ascii=False),
                    json.dumps(merged_streams, ensure_ascii=False),
                )
            )

    def get_strix_results(self) -> List[Dict]:
        """Retrieve all saved Strix results ordered by most recent."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT ip, session_id, probe_json, streams_json, is_garbage, updated_at FROM strix_results ORDER BY updated_at DESC"
            ).fetchall()
            results = []
            for r in rows:
                raw_streams = json.loads(r["streams_json"]) if r["streams_json"] else []
                # Prioritize verified working streams (with codecs, resolution or screenshot) first
                if raw_streams and isinstance(raw_streams, list):
                    raw_streams = sorted(raw_streams, key=lambda s: (
                        0 if (s.get("screenshot") and s.get("codecs")) else
                        1 if (s.get("codecs") or (s.get("width") and s.get("height"))) else
                        2 if s.get("screenshot") else
                        3
                    ))
                results.append({
                    "ip": r["ip"],
                    "session_id": r["session_id"],
                    "probe": json.loads(r["probe_json"]) if r["probe_json"] else {},
                    "streams": raw_streams,
                    "is_garbage": bool(r["is_garbage"]) if "is_garbage" in r.keys() else False,
                    "timestamp": r["updated_at"],
                })
            return results

    def set_strix_garbage_status(self, ip: str, is_garbage: bool) -> bool:
        """Set garbage (non-working / junk) status for a Strix IP result."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE strix_results SET is_garbage = ?, updated_at = CURRENT_TIMESTAMP WHERE ip = ?",
                (1 if is_garbage else 0, str(ip).strip())
            )
            conn.commit()
            return True

    def clear_strix_results(self):
        """Clear all stored Strix results."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM strix_results")

    def create_strix_job(self, job_id: str, targets: list, params: dict) -> dict:
        """Create a persistent Strix scan job entry in SQLite."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO strix_scan_jobs 
                (job_id, status, targets_json, total_targets, current_index, current_ip, progress_pct, stage, params_json, logs_json, created_at, updated_at)
                VALUES (?, 'running', ?, ?, 0, '', 0, 'Запуск сканирования...', ?, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = 'running',
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    str(job_id),
                    json.dumps(targets or [], ensure_ascii=False),
                    len(targets or []),
                    json.dumps(params or {}, ensure_ascii=False)
                )
            )
        return self.get_strix_job(job_id)

    def get_strix_job(self, job_id: str) -> Optional[dict]:
        """Fetch Strix scan job details by job_id."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM strix_scan_jobs WHERE job_id = ?", (str(job_id),)).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "total_targets": int(row["total_targets"] or 0),
                "current_index": int(row["current_index"] or 0),
                "current_ip": row["current_ip"] or "",
                "progress_pct": int(row["progress_pct"] or 0),
                "stage": row["stage"] or "",
                "targets": json.loads(row["targets_json"]) if row["targets_json"] else [],
                "params": json.loads(row["params_json"]) if row["params_json"] else {},
                "logs": json.loads(row["logs_json"]) if row["logs_json"] else [],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def update_strix_job_progress(self, job_id: str, current_index: int, current_ip: str, progress_pct: int, stage: str, status: str = "running", logs: list = None):
        """Update job checkpoint in SQLite."""
        with self._get_connection() as conn:
            if logs is not None:
                conn.execute(
                    """
                    UPDATE strix_scan_jobs
                    SET current_index = ?, current_ip = ?, progress_pct = ?, stage = ?, status = ?, logs_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, current_ip, progress_pct, stage, status, json.dumps(logs[-100:] if logs else [], ensure_ascii=False), str(job_id))
                )
            else:
                conn.execute(
                    """
                    UPDATE strix_scan_jobs
                    SET current_index = ?, current_ip = ?, progress_pct = ?, stage = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, current_ip, progress_pct, stage, status, str(job_id))
                )

    def get_active_strix_job(self) -> Optional[dict]:
        """Fetch most recent active/running Strix scan job to resume upon restart."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM strix_scan_jobs WHERE status IN ('running', 'queued') ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "total_targets": int(row["total_targets"] or 0),
                "current_index": int(row["current_index"] or 0),
                "current_ip": row["current_ip"] or "",
                "progress_pct": int(row["progress_pct"] or 0),
                "stage": row["stage"] or "",
                "targets": json.loads(row["targets_json"]) if row["targets_json"] else [],
                "params": json.loads(row["params_json"]) if row["params_json"] else {},
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def save_strix_scanned_cidr(self, cidr: str, asn: str = "", total_ips: int = 0, cameras_found: int = 0):
        """Record or update a completed scanned CIDR network in SQLite."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO strix_scanned_cidrs (cidr, asn, total_ips, cameras_found, scanned_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cidr) DO UPDATE SET
                    asn = excluded.asn,
                    total_ips = excluded.total_ips,
                    cameras_found = excluded.cameras_found,
                    scanned_at = CURRENT_TIMESTAMP
                """,
                (str(cidr).strip(), str(asn or "").strip(), int(total_ips), int(cameras_found))
            )

    def get_strix_scanned_cidrs(self) -> List[Dict]:
        """Retrieve all recorded scanned CIDR networks."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT cidr, asn, total_ips, cameras_found, scanned_at FROM strix_scanned_cidrs ORDER BY scanned_at DESC"
            ).fetchall()
            return [
                {
                    "cidr": r["cidr"],
                    "asn": r["asn"],
                    "total_ips": r["total_ips"],
                    "cameras_found": r["cameras_found"],
                    "scanned_at": r["scanned_at"],
                }
                for r in rows
            ]

    def get_strix_scanned_cidr_set(self) -> set:
        """Retrieve a fast lookup set of all previously scanned CIDR networks."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT cidr FROM strix_scanned_cidrs").fetchall()
            return {r["cidr"] for r in rows if r["cidr"]}

