"""Active background jobs and hidden graph nodes persistence mixin."""
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class JobsStorageMixin:
    def upsert_job(
        self,
        job_id: str,
        job_type: str = "scan",
        target: str = "",
        status: str = "queued",
        progress_pct: int = 0,
        stage: str = "",
        error: Optional[str] = None,
        meta: Optional[Dict] = None,
    ):
        """Insert or update a job record in SQLite."""
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO active_jobs
                    (job_id, job_type, target, status, progress_pct, stage, error, meta_json, created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(job_id) DO UPDATE SET
                    status       = excluded.status,
                    progress_pct = excluded.progress_pct,
                    stage        = excluded.stage,
                    error        = excluded.error,
                    meta_json    = excluded.meta_json,
                    updated_at   = CURRENT_TIMESTAMP
                """,
                (job_id, job_type, target, status, progress_pct, stage, error, meta_json),
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict]:
        """Fetch a single job record by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM active_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return None
            job = dict(row)
            job.update(json.loads(job.pop("meta_json", "{}") or "{}"))
            return job

    def list_jobs(self, job_type: Optional[str] = None, status_filter: Optional[List[str]] = None) -> List[Dict]:
        """List jobs matching the specified type and status filters."""
        conditions, params = [], []
        if job_type:
            conditions.append("job_type = ?")
            params.append(job_type)
        if status_filter:
            placeholders = ",".join("?" * len(status_filter))
            conditions.append(f"status IN ({placeholders})")
            params.extend(status_filter)
        where = " AND ".join(conditions) if conditions else "1=1"
        with self._get_connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM active_jobs WHERE {where} ORDER BY updated_at", params
            ).fetchall()
        jobs = []
        for row in rows:
            job = dict(row)
            job.update(json.loads(job.pop("meta_json", "{}") or "{}"))
            jobs.append(job)
        return jobs

    def purge_stale_jobs(self) -> int:
        """On server startup: mark any jobs left in running state as 'interrupted'."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                UPDATE active_jobs
                SET status = 'interrupted',
                    error  = 'Server was restarted while this job was running.',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status NOT IN ('completed', 'error', 'interrupted')
            """)
            conn.commit()
            return cur.rowcount

    def hide_nodes(self, node_ids: List[str]):
        """Persist a list of hidden graph node IDs."""
        with self._get_connection() as conn:
            for node_id in node_ids:
                conn.execute("INSERT OR IGNORE INTO hidden_nodes (node_id) VALUES (?)", (node_id,))
            conn.commit()

    def unhide_nodes(self, node_ids: List[str]):
        """Remove a list of node IDs from the hidden_nodes table."""
        with self._get_connection() as conn:
            for node_id in node_ids:
                conn.execute("DELETE FROM hidden_nodes WHERE node_id = ?", (node_id,))
            conn.commit()

    def clear_hidden_nodes(self):
        """Unhide all nodes by clearing the hidden_nodes table."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM hidden_nodes")
            conn.commit()

    def get_hidden_nodes(self) -> List[str]:
        """Fetch all currently hidden node IDs from SQLite."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT node_id FROM hidden_nodes").fetchall()
            return [r["node_id"] for r in rows]
