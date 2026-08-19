"""Recon scan history, global graph results, and node positions mixin."""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ReconStorageMixin:
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

    def save_node_positions(self, positions: Dict[str, Dict[str, float]]):
        """Saves node_id -> {x: 123.4, y: 567.8} coordinates batch into SQLite."""
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
        """Retrieves all saved node coordinates: {node_id: {x: 123, y: 456}}."""
        positions = {}
        with self._get_connection() as conn:
            rows = conn.execute("SELECT node_id, x, y FROM node_positions").fetchall()
            for r in rows:
                positions[r["node_id"]] = {"x": r["x"], "y": r["y"]}
        return positions
