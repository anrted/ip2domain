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
            # Ensure columns ports_json and updated_at exist in wp_scan_results
            try:
                conn.execute("ALTER TABLE wp_scan_results ADD COLUMN ports_json TEXT DEFAULT '[]';")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE wp_scan_results ADD COLUMN updated_at TIMESTAMP;")
            except Exception:
                pass

            # Deduplicate any past duplicate rows by host (keeping the latest record)
            try:
                conn.execute("""
                    DELETE FROM wp_scan_results 
                    WHERE id NOT IN (
                        SELECT MAX(id) FROM wp_scan_results GROUP BY LOWER(TRIM(host))
                    )
                """)
            except Exception:
                pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_results_job ON wp_scan_results(job_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wp_results_wp ON wp_scan_results(is_wordpress);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wp_results_host_unique ON wp_scan_results(host);")
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
        """
        Save or merge WordPress scan results into a single consolidated card per website.
        If a host was already scanned (e.g. port 80 and 443, or repeated scan),
        merges ports, plugins, and security findings into the existing record.
        """
        self._init_wordpress_tables()
        if not results:
            return
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            for r in results:
                host = str(r.get("host") or "").strip().lower()
                if not host:
                    continue

                existing_row = conn.execute(
                    "SELECT * FROM wp_scan_results WHERE LOWER(TRIM(host)) = ?", (host,)
                ).fetchone()

                new_port = r.get("port") or 80
                new_scheme = r.get("scheme") or "http"
                new_is_wp = 1 if r.get("is_wordpress") else 0
                new_status = r.get("status_code")
                new_ver = r.get("version")
                new_ver_src = r.get("version_source")
                new_title = r.get("title") or ""
                new_server = r.get("server") or ""
                new_theme = r.get("theme") or ""
                new_plugins = set(r.get("plugins") or [])
                new_sec = r.get("security") or {}
                new_lat = r.get("latency_ms") or 0.0

                if existing_row:
                    row_dict = dict(existing_row)

                    # 1. Ports consolidation
                    try:
                        old_ports = set(json.loads(row_dict.get("ports_json") or "[]"))
                    except Exception:
                        old_ports = set()
                    if row_dict.get("port"):
                        old_ports.add(row_dict.get("port"))
                    old_ports.add(new_port)
                    merged_ports = sorted(list(old_ports))

                    # 2. Scheme & primary port (prefer https:443 or HTTP 200)
                    has_https = (new_scheme == "https") or (row_dict.get("scheme") == "https") or (443 in merged_ports)
                    primary_scheme = "https" if has_https else "http"
                    if 443 in merged_ports and primary_scheme == "https":
                        primary_port = 443
                    elif new_status == 200:
                        primary_port = new_port
                    elif row_dict.get("status_code") == 200:
                        primary_port = row_dict.get("port", 80)
                    else:
                        primary_port = new_port or row_dict.get("port", 80)

                    if (primary_scheme == "http" and primary_port == 80) or (primary_scheme == "https" and primary_port == 443):
                        canonical_url = f"{primary_scheme}://{host}"
                    else:
                        canonical_url = f"{primary_scheme}://{host}:{primary_port}"

                    # 3. Status code
                    if new_status == 200 or row_dict.get("status_code") == 200:
                        status_code = 200
                    else:
                        status_code = new_status or row_dict.get("status_code")

                    # 4. is_wordpress
                    is_wp = 1 if (new_is_wp or row_dict.get("is_wordpress")) else 0

                    # 5. Version
                    version = new_ver or row_dict.get("version")
                    version_src = new_ver_src if new_ver else row_dict.get("version_source")

                    # 6. Title, server, theme
                    title = new_title if new_title else (row_dict.get("title") or "")
                    server = new_server if new_server else (row_dict.get("server") or "")
                    theme = new_theme if new_theme else (row_dict.get("theme") or "")

                    # 7. Plugins
                    try:
                        old_plugs = set(json.loads(row_dict.get("plugins_json") or "[]"))
                    except Exception:
                        old_plugs = set()
                    merged_plugins = sorted(list(old_plugs | new_plugins))

                    # 8. Security
                    try:
                        old_sec = json.loads(row_dict.get("security_json") or "{}")
                    except Exception:
                        old_sec = {}
                    merged_sec = dict(old_sec)
                    merged_sec.update(new_sec)
                    merged_sec["xmlrpc_open"] = bool(old_sec.get("xmlrpc_open") or new_sec.get("xmlrpc_open"))
                    merged_sec["wp_cron_open"] = bool(old_sec.get("wp_cron_open") or new_sec.get("wp_cron_open"))
                    merged_sec["registration_open"] = bool(old_sec.get("registration_open") or new_sec.get("registration_open"))
                    merged_sec["debug_log_exposed"] = bool(old_sec.get("debug_log_exposed") or new_sec.get("debug_log_exposed"))
                    merged_sec["config_exposed"] = bool(old_sec.get("config_exposed") or new_sec.get("config_exposed"))
                    merged_sec["git_exposed"] = bool(old_sec.get("git_exposed") or new_sec.get("git_exposed"))
                    merged_sec["install_open"] = bool(old_sec.get("install_open") or new_sec.get("install_open"))
                    merged_sec["oembed_proxy_open"] = bool(old_sec.get("oembed_proxy_open") or new_sec.get("oembed_proxy_open"))
                    merged_sec["woocommerce_active"] = bool(old_sec.get("woocommerce_active") or new_sec.get("woocommerce_active"))
                    merged_sec["upgrade_open"] = bool(old_sec.get("upgrade_open") or new_sec.get("upgrade_open"))
                    merged_sec["upgrade_pending"] = bool(old_sec.get("upgrade_pending") or new_sec.get("upgrade_pending"))
                    merged_sec["setup_config_open"] = bool(old_sec.get("setup_config_open") or new_sec.get("setup_config_open"))
                    merged_sec["phpinfo_exposed"] = bool(old_sec.get("phpinfo_exposed") or new_sec.get("phpinfo_exposed"))

                    old_users = set(old_sec.get("users_exposed") or [])
                    new_users = set(new_sec.get("users_exposed") or [])
                    merged_sec["users_exposed"] = sorted(list(old_users | new_users))[:15]

                    cve_map = {}
                    for c in (old_sec.get("cves") or []):
                        if isinstance(c, dict) and c.get("cve"):
                            cve_map[c["cve"]] = c
                    for c in (new_sec.get("cves") or []):
                        if isinstance(c, dict) and c.get("cve"):
                            cve_map[c["cve"]] = c
                    merged_sec["cves"] = list(cve_map.values())
                    merged_sec["wp2shell_vulnerable"] = bool(old_sec.get("wp2shell_vulnerable") or new_sec.get("wp2shell_vulnerable"))
                    merged_sec["has_critical_cve"] = any(c.get("severity") == "CRITICAL" for c in merged_sec["cves"])

                    # 9. Latency
                    old_lat = row_dict.get("latency_ms") or 0.0
                    lat = min(new_lat, old_lat) if (new_lat > 0 and old_lat > 0) else max(new_lat, old_lat)

                    conn.execute("""
                        UPDATE wp_scan_results SET
                            job_id = ?, url = ?, port = ?, scheme = ?, status_code = ?,
                            is_wordpress = ?, version = ?, version_source = ?, title = ?,
                            server = ?, theme = ?, plugins_json = ?, security_json = ?,
                            ports_json = ?, latency_ms = ?, updated_at = ?
                        WHERE id = ?
                    """, (
                        job_id, canonical_url, primary_port, primary_scheme, status_code,
                        is_wp, version, version_src, title[:250],
                        server[:100], theme[:100],
                        json.dumps(merged_plugins, ensure_ascii=False),
                        json.dumps(merged_sec, ensure_ascii=False),
                        json.dumps(merged_ports, ensure_ascii=False),
                        lat, now_str, row_dict["id"]
                    ))

                else:
                    # Insert new consolidated record
                    ports_list = [new_port]
                    url = r.get("url") or f"{new_scheme}://{host}"
                    conn.execute("""
                        INSERT INTO wp_scan_results (
                            job_id, url, host, port, scheme, status_code, is_wordpress,
                            version, version_source, title, server, theme,
                            plugins_json, security_json, ports_json, latency_ms, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        job_id, url, host, new_port, new_scheme, new_status, new_is_wp,
                        new_ver, new_ver_src, new_title[:250], new_server[:100], new_theme[:100],
                        json.dumps(sorted(list(new_plugins)), ensure_ascii=False),
                        json.dumps(new_sec, ensure_ascii=False),
                        json.dumps(ports_list, ensure_ascii=False),
                        new_lat, now_str, now_str
                    ))

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
                try:
                    row_dict["ports"] = json.loads(row_dict.get("ports_json") or "[]")
                except Exception:
                    row_dict["ports"] = []
                if not row_dict["ports"] and row_dict.get("port"):
                    row_dict["ports"] = [row_dict.get("port")]
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
