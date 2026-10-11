"""Camera Scanner v2 — SQLite storage mixin."""
from __future__ import annotations

import json
import logging
import time
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
                    device_category TEXT DEFAULT '',
                    has_preview INTEGER DEFAULT 0,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_brand
                ON v2_results(brand, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_active
                ON v2_results(is_garbage, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_cat
                ON v2_results(device_category, is_garbage)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_preview
                ON v2_results(is_garbage, has_preview DESC, updated_at DESC)
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
            # Auto-migrate tables if created with earlier schema
            res_cols = [r[1] for r in conn.execute("PRAGMA table_info(v2_results)").fetchall()]
            if "device_category" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN device_category TEXT DEFAULT ''")
                    conn.execute("""
                        UPDATE v2_results SET device_category = 
                        CASE 
                            WHEN result_json LIKE '%"device_category": "router"%' OR result_json LIKE '%"categories":%"router"%' THEN 'router'
                            WHEN result_json LIKE '%"device_category": "intercom"%' THEN 'intercom'
                            WHEN result_json LIKE '%"device_category": "generic_web"%' THEN 'generic_web'
                            WHEN result_json LIKE '%"device_category": "sprecord"%' OR result_json LIKE '%"sprecord"%' THEN 'sprecord'
                            WHEN result_json LIKE '%"device_category": "device"%' THEN 'device'
                            ELSE 'camera'
                        END
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_v2_results_cat ON v2_results(device_category, is_garbage)")
                except Exception:
                    pass
            if "has_preview" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN has_preview INTEGER DEFAULT 0")
                    conn.execute("""
                        UPDATE v2_results SET has_preview = 
                        CASE 
                            WHEN streams_json LIKE '%/v2_captures/%' OR streams_json LIKE '%"screenshot": "/%' OR result_json LIKE '%"web_screenshot": "/%' THEN 1
                            ELSE 0
                        END
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_v2_results_preview ON v2_results(is_garbage, has_preview DESC, updated_at DESC)")
                except Exception:
                    pass

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
            if "stage1_hosts_json" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN stage1_hosts_json TEXT DEFAULT ''")
                except Exception:
                    pass
            conn.commit()

    def save_v2_result(self, result: Dict) -> None:
        """Upsert a single camera result from v2 scanner."""
        ip = str(result.get("ip", "")).strip()
        if not ip:
            return
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            result = dict(result)
            if previous:
                old = json.loads(previous[0])
                streams = {s["url"]: s for s in old.get("streams", []) if s.get("url")}
                for stream in result.get("streams", []):
                    if stream.get("url"):
                        streams[stream["url"]] = stream
                result["streams"] = list(streams.values())
                for key in ("protocols", "open_ports"):
                    result[key] = list(dict.fromkeys(old.get(key, []) + result.get(key, [])))
                def endpoint_key(e):
                    return (e.get("port"), e.get("transport", "tcp"), tuple(sorted(e.get("protocols", []))))
                endpoints = {endpoint_key(e): e for e in old.get("endpoints", [])}
                endpoints.update({endpoint_key(e): e for e in result.get("endpoints", [])})
                result["endpoints"] = list(endpoints.values())
                if not result.get("credentials") and old.get("credentials"):
                    result["credentials"] = old["credentials"]

            cat = str(result.get("device_category", "")).strip().lower()
            if not cat:
                if any("sprecord" in str(x).lower() for x in (result.get("brand", ""), result.get("model", ""), result.get("protocols", []))):
                    cat = "sprecord"
                elif "router" in str(result.get("protocols", [])) or "winbox" in str(result.get("protocols", [])):
                    cat = "router"
                elif any("intercom" in str(x).lower() for x in (result.get("categories", []), result.get("brand", ""))):
                    cat = "intercom"
                elif any("generic_web" in str(x).lower() for x in (result.get("categories", []), result.get("brand", ""))):
                    cat = "generic_web"
                elif result.get("device_category"):
                    cat = str(result["device_category"])
                else:
                    cat = "camera"
            result["device_category"] = cat

            has_prev = 1 if (
                any(bool(s.get("screenshot")) for s in result.get("streams", []))
                or bool(result.get("web_screenshot"))
            ) else 0

            conn.execute(
                """
                INSERT INTO v2_results (ip, brand, model, serial, protocols, streams_json, result_json, device_category, has_preview, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    brand = excluded.brand,
                    model = excluded.model,
                    serial = excluded.serial,
                    protocols = excluded.protocols,
                    streams_json = excluded.streams_json,
                    result_json = excluded.result_json,
                    device_category = excluded.device_category,
                    has_preview = excluded.has_preview,
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
                    cat,
                    has_prev,
                ),
            )

    def update_v2_stream(self, ip: str, stream: Dict) -> None:
        """Persist one captured URL without rolling back other concurrent updates."""
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return
            result = json.loads(row[0])
            for existing in result.get("streams", []):
                if existing.get("url") == stream.get("url"):
                    existing.update(stream)
                    break
            else:
                return
            has_prev = 1 if (
                any(bool(s.get("screenshot")) for s in result.get("streams", []))
                or bool(result.get("web_screenshot"))
            ) else 0
            conn.execute("UPDATE v2_results SET result_json = ?, streams_json = ?, has_preview = ? WHERE ip = ?",
                         (json.dumps(result, ensure_ascii=False), json.dumps(result.get("streams", []), ensure_ascii=False), has_prev, ip))

    def update_v2_geo(self, ip: str, geo: Dict) -> bool:
        """Update only geolocation, preserving concurrently captured frames."""
        keys = {"city", "region", "country_code", "isp", "geo_precision", "geo_source",
                "geo_accuracy_radius_km", "geo_database_date"}
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return False
            result = json.loads(row[0])
            changed = any(result.get(key) != value for key, value in geo.items() if key in keys)
            if changed:
                result.update({key: value for key, value in geo.items() if key in keys})
                conn.execute("UPDATE v2_results SET result_json = ? WHERE ip = ?",
                             (json.dumps(result, ensure_ascii=False), ip))
            return changed

    def _build_v2_where_clause(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> Tuple[str, List]:
        where = " WHERE is_garbage = 0"
        params = []
        if brand and brand != "all":
            where += " AND brand LIKE ?"
            params.append(f"%{brand}%")
        if protocol and protocol != "all":
            where += " AND protocols LIKE ?"
            params.append(f"%{protocol}%")
        if category and category != "all":
            where += " AND (device_category = ? OR result_json LIKE ?)"
            params.append(category)
            params.append(f'%"device_category": "{category}"%')
        if has_preview:
            where += " AND has_preview = 1"
        elif verified_only:
            where += " AND (has_preview = 1 OR streams_json LIKE '%\"verified\": true%')"
        if auth_status in ("401", "locked", "auth_required"):
            where += " AND result_json LIKE '%\"auth_required\": true%'"
        elif auth_status in ("open", "unauthenticated", "no_auth"):
            where += " AND (streams_json LIKE '%\"verified\": true%' OR (result_json LIKE '%\"auth_required\": false%' AND streams_json LIKE '%\"url\"%'))"
        if geo and geo != "all":
            if geo == "__no_geo__":
                where += " AND (result_json NOT LIKE '%\"city\"%' OR result_json LIKE '%\"city\": \"\"%')"
            elif geo.startswith("country:"):
                code = geo.replace("country:", "").upper()
                where += " AND json_extract(result_json, '$.country_code') = ?"
                params.append(code)
            elif geo.startswith("region:"):
                reg = geo.replace("region:", "")
                where += " AND json_extract(result_json, '$.region') = ?"
                params.append(reg)
            elif geo.startswith("city:"):
                cit = geo.replace("city:", "")
                where += " AND json_extract(result_json, '$.city') = ?"
                params.append(cit)
        if search:
            s = search.strip()
            where += " AND (ip LIKE ? OR brand LIKE ? OR model LIKE ? OR result_json LIKE ?)"
            params.extend([f"%{s}%", f"%{s}%", f"%{s}%", f"%{s}%"])
        return where, params

    def get_v2_results(
        self,
        limit: int = 48,
        offset: int = 0,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> List[Dict]:
        """Retrieve v2 scanner results with server-side pagination and SQL filtering."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT result_json, in_go2rtc FROM v2_results{where_clause}"
            query += " ORDER BY has_preview DESC, updated_at DESC"
            if limit and limit > 0:
                query += " LIMIT ?"
                params.append(limit)
                if offset and offset > 0:
                    query += " OFFSET ?"
                    params.append(offset)

            from ip2domain.data.geo_city_db import normalize_geo
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                try:
                    r = json.loads(row["result_json"])
                    clean_geo = normalize_geo(r)
                    r.update(city=clean_geo["city"], region=clean_geo["region"])
                    r.setdefault("geo_precision", clean_geo["precision"])
                    r["in_go2rtc"] = bool(row["in_go2rtc"])

                    if "auth_required" not in r:
                        r["auth_required"] = None

                    results.append(r)
                except Exception:
                    pass

            return results

    def get_v2_results_count(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> int:
        """Count total results matching the query filters."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT COUNT(*) FROM v2_results{where_clause}"
            row = conn.execute(query, params).fetchone()
            return row[0] if row else 0

    def get_v2_filtered_ips(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> List[str]:
        """Return list of distinct clean IP addresses matching the query filters."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT DISTINCT ip FROM v2_results{where_clause} ORDER BY ip"
            rows = conn.execute(query, params).fetchall()
            ips = []
            for (raw_ip,) in rows:
                ip = (raw_ip or "").strip()
                if ip.startswith("http://") or ip.startswith("https://"):
                    ip = ip.split("//")[-1].split("/")[0]
                if ":" in ip and not ip.startswith("["):
                    ip = ip.split(":")[0]
                if ip:
                    ips.append(ip)
            return ips

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
        """Return protocol, brand, category and global geo statistics for v2 results with TTL cache."""
        now = time.time()
        cached = getattr(self, "_v2_stats_cache", None)
        if cached and (now - cached.get("ts", 0) < 120):
            return cached["data"]

        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM v2_results WHERE is_garbage=0").fetchone()[0]
            by_brand = {}
            for row in conn.execute(
                "SELECT brand, COUNT(*) as cnt FROM v2_results WHERE is_garbage=0 GROUP BY brand ORDER BY cnt DESC LIMIT 50"
            ).fetchall():
                by_brand[row["brand"] or "Unknown"] = row["cnt"]

            by_category = {}
            for row in conn.execute(
                "SELECT device_category, COUNT(*) as cnt FROM v2_results WHERE is_garbage=0 GROUP BY device_category"
            ).fetchall():
                cat = row["device_category"] or "camera"
                by_category[cat] = row["cnt"]

            by_country = {}
            for row in conn.execute(
                "SELECT json_extract(result_json, '$.country_code') as cc, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND json_extract(result_json, '$.country_code') IS NOT NULL "
                "AND json_extract(result_json, '$.country_code') != '' GROUP BY cc ORDER BY cnt DESC LIMIT 30"
            ).fetchall():
                by_country[row["cc"]] = row["cnt"]

            by_city = {}
            for row in conn.execute(
                "SELECT json_extract(result_json, '$.city') as c, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND json_extract(result_json, '$.city') IS NOT NULL "
                "AND json_extract(result_json, '$.city') != '' GROUP BY c ORDER BY cnt DESC LIMIT 200"
            ).fetchall():
                by_city[row["c"]] = row["cnt"]

            by_region = {}
            for row in conn.execute(
                "SELECT json_extract(result_json, '$.region') as r, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND json_extract(result_json, '$.region') IS NOT NULL "
                "AND json_extract(result_json, '$.region') != '' GROUP BY r ORDER BY cnt DESC LIMIT 100"
            ).fetchall():
                by_region[row["r"]] = row["cnt"]

            data = {
                "total": total,
                "by_brand": by_brand,
                "by_category": by_category,
                "by_country": by_country,
                "by_city": by_city,
                "by_region": by_region,
            }
            self._v2_stats_cache = {"ts": now, "data": data}
            return data

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

    def save_v2_stage1_hosts(self, job_id: str, responsive_hosts: list) -> None:
        """Persist Stage 1 responsive hosts [(ip, [ports]), ...] to DB for restart survival."""
        data = json.dumps(responsive_hosts, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_jobs SET stage1_hosts_json = ?, updated_at = CURRENT_TIMESTAMP WHERE job_id = ?",
                (data, job_id),
            )

    def get_v2_stage1_hosts(self, job_id: str) -> list:
        """Load saved Stage 1 responsive hosts for auto-resume into Stage 2."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT stage1_hosts_json FROM v2_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if not row or not row[0]:
                return []
            try:
                return json.loads(row[0])
            except Exception:
                return []
