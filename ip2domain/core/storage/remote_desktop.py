"""Remote desktop (RDP / VNC) services storage mixin."""
import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class RemoteDesktopStorageMixin:
    def save_remote_desktop_services(self, services: List[Dict[str, any]]) -> None:
        with self._get_connection() as conn:
            for service in services:
                target = str(service.get("target") or "").strip()
                port = int(service.get("port") or 0)
                protocol_type = str(service.get("protocol_type") or "").strip().lower()
                if not target or not port or not protocol_type:
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

    def get_remote_desktop_services(self, limit: int = 1000) -> List[Dict[str, any]]:
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
