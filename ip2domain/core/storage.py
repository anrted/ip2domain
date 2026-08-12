import json
import sqlite3
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Default DB path: adjacent to the package root (ip2domain.db next to the ip2domain/ folder)
_DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent.parent / "ip2domain.db")
DB_PATH = os.environ.get("IP2DOMAIN_DB_PATH", _DEFAULT_DB_PATH)


class StorageManager:
    """
    SQLite persistence manager for scan history, results, and topology graphs.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verify INTEGER DEFAULT 0,
                    nmap INTEGER DEFAULT 0,
                    total_ips INTEGER DEFAULT 0,
                    total_domains INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'completed',
                    results_json TEXT,
                    graph_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS http_analysis (
                    target TEXT PRIMARY KEY,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_analysis (
                    target TEXT PRIMARY KEY,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS node_positions (
                    node_id TEXT PRIMARY KEY,
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Persistent job state table — survives server restarts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_jobs (
                    job_id     TEXT PRIMARY KEY,
                    job_type   TEXT NOT NULL DEFAULT 'scan',
                    target     TEXT,
                    status     TEXT NOT NULL DEFAULT 'queued',
                    progress_pct INTEGER DEFAULT 0,
                    stage      TEXT,
                    error      TEXT,
                    meta_json  TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Persistent hidden nodes table — saves hidden graph nodes on server
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hidden_nodes (
                    node_id   TEXT PRIMARY KEY,
                    hidden_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS camera_devices (
                    target TEXT PRIMARY KEY,
                    hostname TEXT,
                    score INTEGER DEFAULT 0,
                    confidence TEXT,
                    device_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_cameras (
                    camera_id TEXT PRIMARY KEY,
                    title TEXT,
                    camera_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remote_desktop_services (
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol_type TEXT NOT NULL,
                    service_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (target, port, protocol_type)
                )
            """)
            conn.commit()

    def save_camera_devices(self, devices: List[Dict[str, any]]) -> None:
        """Upsert camera observations, retaining devices found by older scans."""
        with self._get_connection() as conn:
            for device in devices:
                target = str(device.get("target", "")).strip()
                if not target:
                    continue
                conn.execute("""
                    INSERT INTO camera_devices
                        (target, hostname, score, confidence, device_json, first_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT(target) DO UPDATE SET
                        hostname=excluded.hostname,
                        score=excluded.score,
                        confidence=excluded.confidence,
                        device_json=excluded.device_json,
                        updated_at=CURRENT_TIMESTAMP
                """, (target, device.get("hostname", ""), device.get("score", 0),
                      device.get("confidence", ""), json.dumps(device, ensure_ascii=False)))
            conn.commit()

    def get_camera_devices(self, limit: int = 1000) -> List[Dict[str, any]]:
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT device_json, first_seen, updated_at
                FROM camera_devices
                ORDER BY score DESC, updated_at DESC, target ASC
                LIMIT ?
            """, (limit,)).fetchall()
        devices = []
        for row in rows:
            device = json.loads(row["device_json"])
            device["first_seen"] = row["first_seen"]
            device["updated_at"] = row["updated_at"]
            devices.append(device)
        return devices

    def clear_camera_devices(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM camera_devices")
            conn.commit()
            return cursor.rowcount

    def save_centra_cameras(self, cameras: List[Dict[str, any]]) -> None:
        with self._get_connection() as conn:
            for camera in cameras:
                camera_id = str(camera.get("id", "")).strip()
                if not camera_id:
                    continue
                conn.execute("""
                    INSERT INTO centra_cameras
                        (camera_id, title, camera_json, first_seen, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT(camera_id) DO UPDATE SET
                        title=excluded.title,
                        camera_json=excluded.camera_json,
                        updated_at=CURRENT_TIMESTAMP
                """, (camera_id, camera.get("title", ""),
                      json.dumps(camera, ensure_ascii=False)))
            conn.commit()

    def get_centra_cameras(self, limit: int = 250000) -> List[Dict[str, any]]:
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT camera_json, first_seen, updated_at FROM centra_cameras
                ORDER BY camera_id LIMIT ?
            """, (limit,)).fetchall()
        result = []
        for row in rows:
            camera = json.loads(row["camera_json"])
            camera["first_seen"] = row["first_seen"]
            camera["updated_at"] = row["updated_at"]
            result.append(camera)
        return result

    def clear_centra_cameras(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM centra_cameras")
            conn.commit()
            return cursor.rowcount

    def save_remote_desktop_services(self, services: List[Dict[str, any]]) -> None:
        """Upsert accumulated RDP/VNC observations in SQLite."""
        with self._get_connection() as conn:
            for service in services:
                target = str(service.get("target", "")).strip()
                port = int(service.get("port", 0))
                protocol_type = str(service.get("protocol_type", "")).strip()
                if not target or not port or protocol_type not in {"rdp", "vnc"}:
                    continue
                conn.execute("""
                    INSERT INTO remote_desktop_services
                        (target, port, protocol_type, service_json, first_seen, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT(target, port, protocol_type) DO UPDATE SET
                        service_json=excluded.service_json,
                        updated_at=CURRENT_TIMESTAMP
                """, (target, port, protocol_type, json.dumps(service, ensure_ascii=False)))
            conn.commit()

    def get_remote_desktop_services(self, limit: int = 5000) -> List[Dict[str, any]]:
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT service_json, first_seen, updated_at
                FROM remote_desktop_services
                ORDER BY updated_at DESC, target ASC, port ASC
                LIMIT ?
            """, (limit,)).fetchall()
        services = []
        for row in rows:
            service = json.loads(row["service_json"])
            service["first_seen"] = row["first_seen"]
            service["updated_at"] = row["updated_at"]
            services.append(service)
        return services

    def clear_remote_desktop_services(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM remote_desktop_services")
            conn.commit()
            return cursor.rowcount

    def hide_nodes(self, node_ids: List[str]) -> None:
        """Saves hidden node IDs to SQLite."""
        with self._get_connection() as conn:
            for n_id in node_ids:
                conn.execute(
                    "INSERT OR REPLACE INTO hidden_nodes (node_id, hidden_at) VALUES (?, CURRENT_TIMESTAMP)",
                    (n_id,)
                )
            conn.commit()

    def get_hidden_nodes(self) -> List[str]:
        """Returns list of hidden node IDs from SQLite."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT node_id FROM hidden_nodes").fetchall()
        return [row["node_id"] for row in rows]

    def unhide_nodes(self, node_ids: List[str]) -> None:
        """Removes node IDs from hidden_nodes table."""
        with self._get_connection() as conn:
            for n_id in node_ids:
                conn.execute("DELETE FROM hidden_nodes WHERE node_id = ?", (n_id,))
            conn.commit()

    def clear_hidden_nodes(self) -> None:
        """Clears all hidden nodes in SQLite."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM hidden_nodes")
            conn.commit()

    def upsert_job(self, job_id: str, job_type: str, state: dict) -> None:
        """Persist job state dict to SQLite active_jobs table."""
        import json as _json
        meta = {k: v for k, v in state.items()
                if k not in ('status', 'progress_pct', 'stage', 'error', 'results', 'graph')}
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO active_jobs (job_id, job_type, target, status, progress_pct, stage, error, meta_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    progress_pct=excluded.progress_pct,
                    stage=excluded.stage,
                    error=excluded.error,
                    meta_json=excluded.meta_json,
                    updated_at=CURRENT_TIMESTAMP
            """, (
                job_id,
                job_type,
                state.get('target'),
                state.get('status', 'queued'),
                state.get('progress_pct', 0),
                state.get('stage'),
                state.get('error'),
                _json.dumps(meta),
            ))
            conn.commit()

    def get_job(self, job_id: str) -> Optional[dict]:
        """Retrieve a persisted job from SQLite."""
        import json as _json
        with self._get_connection() as conn:
            row = conn.execute(
                'SELECT * FROM active_jobs WHERE job_id = ?', (job_id,)
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        meta = _json.loads(result.pop('meta_json', '{}') or '{}')
        result.update(meta)
        return result

    def purge_stale_jobs(self) -> int:
        """
        On server startup: mark any jobs that were left in queued/running state
        as 'interrupted' (they died mid-execution when the server restarted).
        Returns the number of jobs updated.
        """
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

    def save_node_positions(self, positions: Dict[str, Dict[str, float]]):
        """
        Saves node_id -> {x: 123.4, y: 567.8} coordinates batch into SQLite.
        """
        with self._get_connection() as conn:
            for node_id, pos in positions.items():
                if "x" in pos and "y" in pos:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO node_positions (node_id, x, y, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (node_id, pos["x"], pos["y"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    )
            conn.commit()

    def get_all_node_positions(self) -> Dict[str, Dict[str, float]]:
        """
        Retrieves all saved node coordinates: {node_id: {x: 123, y: 456}}
        """
        positions = {}
        with self._get_connection() as conn:
            rows = conn.execute("SELECT node_id, x, y FROM node_positions").fetchall()
            for r in rows:
                positions[r["node_id"]] = {"x": r["x"], "y": r["y"]}
        return positions

    def save_vuln_analysis(self, target: str, analysis: Dict[str, any]):
        target_clean = target.strip().lower()
        analysis_str = json.dumps(analysis, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vuln_analysis (target, updated_at, analysis_json)
                VALUES (?, ?, ?)
                """,
                (target_clean, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), analysis_str),
            )
            conn.commit()

    def get_vuln_analysis(self, target: str) -> Optional[Dict[str, any]]:
        target_clean = target.strip().lower()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM vuln_analysis WHERE target = ?", (target_clean,)
            ).fetchone()
            if row and row["analysis_json"]:
                return json.loads(row["analysis_json"])
        return None

    def save_http_analysis(self, target: str, analysis: Dict[str, any]):
        target_clean = target.strip().lower()
        analysis_str = json.dumps(analysis, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO http_analysis (target, updated_at, analysis_json)
                VALUES (?, ?, ?)
                """,
                (target_clean, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), analysis_str),
            )
            conn.commit()

    def get_http_analysis(self, target: str) -> Optional[Dict[str, any]]:
        target_clean = target.strip().lower()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM http_analysis WHERE target = ?", (target_clean,)
            ).fetchone()
            if row and row["analysis_json"]:
                return json.loads(row["analysis_json"])
        return None

    def save_scan(
        self,
        job_id: str,
        target: str,
        verify: bool,
        nmap: bool,
        total_ips: int,
        total_domains: int,
        results: List[Dict[str, any]],
        graph: Dict[str, any],
        status: str = "completed",
    ):
        results_str = json.dumps(results, ensure_ascii=False)
        graph_str = json.dumps(graph, ensure_ascii=False)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_history 
                (id, target, created_at, verify, nmap, total_ips, total_domains, status, results_json, graph_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    target,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    1 if verify else 0,
                    1 if nmap else 0,
                    total_ips,
                    total_domains,
                    status,
                    results_str,
                    graph_str,
                ),
            )
            conn.commit()

    def list_history(self, limit: int = 50) -> List[Dict[str, any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, target, created_at, verify, nmap, total_ips, total_domains, status
                FROM scan_history
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_scan(self, job_id: str) -> Optional[Dict[str, any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ?", (job_id,)
            ).fetchone()

            if not row:
                return None

            data = dict(row)
            data["verify"] = bool(data["verify"])
            data["nmap"] = bool(data["nmap"])
            data["results"] = json.loads(data["results_json"]) if data["results_json"] else []
            data["graph"] = json.loads(data["graph_json"]) if data["graph_json"] else {"nodes": [], "edges": [], "stats": {}}
            return data

    def delete_scan(self, job_id: str):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM scan_history WHERE id = ?", (job_id,))
            conn.commit()

    def get_global_scan_results(self) -> List[Dict[str, any]]:
        """
        Builds the current topology from the newest successful scan per target.
        Current observations from different targets are merged so one scan cannot
        erase relationships owned by another target.
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT current.results_json
                FROM scan_history AS current
                WHERE current.status = 'completed'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM scan_history AS newer
                      WHERE newer.status = 'completed'
                        AND lower(trim(newer.target)) = lower(trim(current.target))
                        AND (
                            newer.created_at > current.created_at
                            OR (newer.created_at = current.created_at AND newer.rowid > current.rowid)
                        )
                  )
                ORDER BY current.created_at ASC, current.rowid ASC
            """).fetchall()

            merged_by_ip: Dict[str, Dict[str, any]] = {}
            for r in rows:
                if not r["results_json"]:
                    continue
                scan_items = json.loads(r["results_json"])
                for item in scan_items:
                    ip = item["ip"]
                    if ip not in merged_by_ip:
                        merged_by_ip[ip] = {
                            "ip": ip,
                            "domains": set(),
                            "provider_details": {},
                            "open_ports": [],
                            "nmap_status": "",
                            "nmap_error": "",
                            "nmap_hostname": "",
                            "nmap_os": "",
                            "nmap_tech_stack": [],
                            "verified_live": False,
                        }
                    current = merged_by_ip[ip]
                    current["domains"].update(item.get("domains", []))
                    current["verified_live"] = (
                        current["verified_live"] or item.get("verified_live", False)
                    )
                    if item.get("nmap_status") == "completed":
                        current["open_ports"] = item["open_ports"]
                    elif item.get("open_ports") and not current["open_ports"]:
                        current["open_ports"] = item["open_ports"]
                    if item.get("nmap_status"):
                        for field in ("nmap_status", "nmap_error", "nmap_hostname", "nmap_os", "nmap_tech_stack"):
                            current[field] = item.get(field, "")
                    for provider, domains in item.get("provider_details", {}).items():
                        existing = set(current["provider_details"].get(provider, []))
                        existing.update(domains)
                        current["provider_details"][provider] = sorted(existing)

            final_list = []
            for ip, data in merged_by_ip.items():
                data["domains"] = sorted(list(data["domains"]))
                data["total_domains"] = len(data["domains"])
                final_list.append(data)

            return final_list
