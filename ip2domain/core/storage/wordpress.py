"""WordPress Hunter persistence storage mixin."""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class WordPressStorageMixin:
    """Storage mixin for WordPress mass discovery jobs and results."""

    def _init_wordpress_tables(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wp_scan_jobs (
                    id TEXT PRIMARY KEY,
                    target_input TEXT NOT NULL,
                    ports_json TEXT,
                    status TEXT DEFAULT 'queued',
                    total_targets INTEGER DEFAULT 0,
                    completed_targets INTEGER DEFAULT 0,
                    found_wp INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wp_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    scheme TEXT NOT NULL,
                    status_code INTEGER,
                    is_wordpress INTEGER DEFAULT 0,
                    version TEXT,
                    version_source TEXT,
                    title TEXT,
                    server TEXT,
                    theme TEXT,
                    plugins_json TEXT,
                    security_json TEXT,
                    latency_ms REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wp_job_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    source_ip TEXT,
                    source_type TEXT DEFAULT 'user_input',
                    port INTEGER DEFAULT 80,
                    scheme TEXT DEFAULT 'http',
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_results_job ON wp_scan_results(job_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_results_wp ON wp_scan_results(is_wordpress);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_results_host ON wp_scan_results(host);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_job_targets_status ON wp_job_targets(job_id, status);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wp_job_targets_uniq ON wp_job_targets(job_id, target, port, scheme);")
            conn.commit()

    def save_wp_job_targets_batch(self, job_id: str, targets: List[Dict[str, Any]]) -> int:
        """Batch save intermediate discovered targets to disk without keeping in RAM."""
        if not targets:
            return 0
        self._init_wordpress_tables()
        tuples = [
            (
                job_id,
                t["target"],
                t.get("source_ip"),
                t.get("source_type", "user_input"),
                t.get("port", 80),
                t.get("scheme", "http"),
            )
            for t in targets
            if t.get("target")
        ]
        with self._get_connection() as conn:
            cur = conn.executemany("""
                INSERT OR IGNORE INTO wp_job_targets (job_id, target, source_ip, source_type, port, scheme)
                VALUES (?, ?, ?, ?, ?, ?)
            """, tuples)
            conn.commit()
            return cur.rowcount

    def count_wp_job_targets(self, job_id: str, status: Optional[str] = None) -> int:
        """Count discovered targets in database for a job."""
        self._init_wordpress_tables()
        query = "SELECT COUNT(*) as cnt FROM wp_job_targets WHERE job_id = ?"
        params: List[Any] = [job_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        with self._get_connection() as conn:
            return conn.execute(query, params).fetchone()["cnt"]

    def get_pending_wp_job_targets(self, job_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        """Fetch a chunk of targets from disk for streaming scan without RAM bloat."""
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT id, target as host, source_ip, source_type, port, scheme
                FROM wp_job_targets
                WHERE job_id = ? AND status = 'pending'
                ORDER BY id ASC
                LIMIT ?
            """, (job_id, limit)).fetchall()
            return [dict(r) for r in rows]

    def mark_wp_job_targets_scanned(self, ids: List[int]) -> None:
        """Mark scanned target IDs in database."""
        if not ids:
            return
        self._init_wordpress_tables()
        placeholders = ",".join("?" for _ in ids)
        with self._get_connection() as conn:
            conn.execute(f"UPDATE wp_job_targets SET status = 'scanned' WHERE id IN ({placeholders})", ids)
            conn.commit()

    def clear_wp_job_targets(self, job_id: Optional[str] = None) -> None:
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            if job_id:
                conn.execute("DELETE FROM wp_job_targets WHERE job_id = ?", (job_id,))
            else:
                conn.execute("DELETE FROM wp_job_targets")
            conn.commit()

    def create_wp_job(self, job_id: str, target_input: str, ports: List[int], total_targets: int) -> Dict[str, Any]:
        self._init_wordpress_tables()
        ports_json = json.dumps(ports)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO wp_scan_jobs 
                (id, target_input, ports_json, status, total_targets, completed_targets, found_wp, created_at)
                VALUES (?, ?, ?, 'running', ?, 0, 0, ?)
            """, (job_id, target_input, ports_json, total_targets, now_str))
            conn.commit()
        return self.get_wp_job(job_id)

    def update_wp_job(
        self,
        job_id: str,
        status: Optional[str] = None,
        completed_targets: Optional[int] = None,
        found_wp: Optional[int] = None,
        finished: bool = False,
    ):
        clauses = []
        params = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if completed_targets is not None:
            clauses.append("completed_targets = ?")
            params.append(completed_targets)
        if found_wp is not None:
            clauses.append("found_wp = ?")
            params.append(found_wp)
        if finished:
            clauses.append("finished_at = ?")
            params.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if not clauses:
            return

        params.append(job_id)
        with self._get_connection() as conn:
            conn.execute(f"UPDATE wp_scan_jobs SET {', '.join(clauses)} WHERE id = ?", params)
            conn.commit()

    def stop_all_wp_jobs(self) -> None:
        self._init_wordpress_tables()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE wp_scan_jobs SET status = 'stopped', finished_at = ? WHERE status IN ('running', 'queued')",
                (now_str,)
            )
            conn.commit()

    def get_wp_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM wp_scan_jobs WHERE id = ?", (job_id,)).fetchone()
            if not row:
                return None
            data = dict(row)
            try:
                data["ports"] = json.loads(data.get("ports_json") or "[]")
            except Exception:
                data["ports"] = []
            return data

    def get_recent_wp_jobs(self, limit: int = 15) -> List[Dict[str, Any]]:
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM wp_scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            jobs = []
            for r in rows:
                item = dict(r)
                try:
                    item["ports"] = json.loads(item.get("ports_json") or "[]")
                except Exception:
                    item["ports"] = []
                jobs.append(item)
            return jobs

    def save_wp_results_batch(self, job_id: str, results: List[Dict[str, Any]]):
        self._init_wordpress_tables()
        if not results:
            return
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tuples = []
        for r in results:
            tuples.append((
                job_id,
                r.get("url", ""),
                r.get("host", ""),
                r.get("port", 80),
                r.get("scheme", "http"),
                r.get("status_code"),
                1 if r.get("is_wordpress") else 0,
                r.get("version"),
                r.get("version_source"),
                r.get("title", "")[:250],
                r.get("server", "")[:100],
                r.get("theme", "")[:100],
                json.dumps(r.get("plugins") or [], ensure_ascii=False),
                json.dumps(r.get("security") or {}, ensure_ascii=False),
                r.get("latency_ms", 0.0),
                now_str,
            ))
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO wp_scan_results (
                    job_id, url, host, port, scheme, status_code, is_wordpress,
                    version, version_source, title, server, theme,
                    plugins_json, security_json, latency_ms, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, tuples)
            conn.commit()

    def get_wp_results(
        self,
        job_id: Optional[str] = None,
        only_wp: bool = True,
        version: Optional[str] = None,
        plugin: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        self._init_wordpress_tables()
        where_clauses = []
        params: List[Any] = []

        if job_id:
            where_clauses.append("job_id = ?")
            params.append(job_id)

        if only_wp:
            where_clauses.append("is_wordpress = 1")

        if version:
            where_clauses.append("version LIKE ?")
            params.append(f"{version}%")

        if plugin:
            where_clauses.append("plugins_json LIKE ?")
            params.append(f"%{plugin}%")

        if search:
            where_clauses.append("(host LIKE ? OR url LIKE ? OR title LIKE ? OR theme LIKE ? OR plugins_json LIKE ? OR security_json LIKE ?)")
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param, s_param, s_param])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        with self._get_connection() as conn:
            total_count = conn.execute(
                f"SELECT COUNT(*) as cnt FROM wp_scan_results {where_sql}", params
            ).fetchone()["cnt"]

            rows = conn.execute(
                f"""SELECT * FROM wp_scan_results {where_sql}
                   ORDER BY is_wordpress DESC, id DESC
                   LIMIT ? OFFSET ?""",
                params + [limit, offset],
            ).fetchall()

            items = []
            for r in rows:
                row_dict = dict(r)
                try:
                    row_dict["plugins"] = json.loads(row_dict.get("plugins_json") or "[]")
                except Exception:
                    row_dict["plugins"] = []
                try:
                    row_dict["security"] = json.loads(row_dict.get("security_json") or "{}")
                except Exception:
                    row_dict["security"] = {}
                items.append(row_dict)

        return {"total": total_count, "items": items, "limit": limit, "offset": offset}

    def get_wp_stats(self) -> Dict[str, Any]:
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            total_scanned = conn.execute("SELECT COUNT(*) as cnt FROM wp_scan_results").fetchone()["cnt"]
            total_wp = conn.execute("SELECT COUNT(*) as cnt FROM wp_scan_results WHERE is_wordpress = 1").fetchone()["cnt"]
            total_versions = conn.execute(
                "SELECT COUNT(*) as cnt FROM wp_scan_results WHERE is_wordpress = 1 AND version IS NOT NULL AND version != ''"
            ).fetchone()["cnt"]

            # Outdated versions (< 6.0)
            outdated_wp = conn.execute("""
                SELECT COUNT(*) as cnt FROM wp_scan_results 
                WHERE is_wordpress = 1 AND version IS NOT NULL AND (
                    version LIKE '1.%' OR version LIKE '2.%' OR version LIKE '3.%' OR version LIKE '4.%' OR version LIKE '5.%'
                )
            """).fetchone()["cnt"]

            # Versions breakdown
            v_rows = conn.execute("""
                SELECT substr(version, 1, 3) as major_ver, COUNT(*) as cnt 
                FROM wp_scan_results 
                WHERE is_wordpress = 1 AND version IS NOT NULL AND version != ''
                GROUP BY major_ver 
                ORDER BY cnt DESC 
                LIMIT 10
            """).fetchall()
            versions_breakdown = {r["major_ver"]: r["cnt"] for r in v_rows}

            # Top themes
            t_rows = conn.execute("""
                SELECT theme, COUNT(*) as cnt 
                FROM wp_scan_results 
                WHERE is_wordpress = 1 AND theme IS NOT NULL AND theme != ''
                GROUP BY theme 
                ORDER BY cnt DESC 
                LIMIT 8
            """).fetchall()
            top_themes = {r["theme"]: r["cnt"] for r in t_rows}

            # Top plugins
            p_rows = conn.execute(
                "SELECT plugins_json FROM wp_scan_results WHERE is_wordpress = 1 AND plugins_json IS NOT NULL"
            ).fetchall()
            plugin_counts: Dict[str, int] = {}
            for r in p_rows:
                try:
                    plist = json.loads(r["plugins_json"])
                    for p in plist:
                        plugin_counts[p] = plugin_counts.get(p, 0) + 1
                except Exception:
                    pass

            top_plugins = dict(sorted(plugin_counts.items(), key=lambda x: x[1], reverse=True)[:10])

        return {
            "total_scanned": total_scanned,
            "total_wp": total_wp,
            "total_versions": total_versions,
            "outdated_wp": outdated_wp,
            "versions_breakdown": versions_breakdown,
            "top_themes": top_themes,
            "top_plugins": top_plugins,
        }

    def clear_wp_results(self, job_id: Optional[str] = None):
        self._init_wordpress_tables()
        with self._get_connection() as conn:
            if job_id:
                conn.execute("DELETE FROM wp_scan_results WHERE job_id = ?", (job_id,))
                conn.execute("DELETE FROM wp_scan_jobs WHERE id = ?", (job_id,))
            else:
                conn.execute("DELETE FROM wp_scan_results")
                conn.execute("DELETE FROM wp_scan_jobs")
            conn.commit()
