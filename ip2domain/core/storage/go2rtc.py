"""go2rtc cameras and groups metadata persistence mixin."""
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class Go2rtcStorageMixin:
    def get_all_go2rtc_meta(self) -> Dict[str, dict]:
        """Fetch all camera and group metadata for go2rtc streams."""
        cameras = {}
        groups = {}
        with self._get_connection() as conn:
            cam_rows = conn.execute("SELECT * FROM go2rtc_camera_meta").fetchall()
            for r in cam_rows:
                cameras[r["stream_name"]] = {
                    "stream_name": r["stream_name"],
                    "custom_title": r["custom_title"] or "",
                    "group_ip": r["group_ip"] or "",
                    "group_name": r["group_name"] or "",
                    "tags": json.loads(r["tags_json"]) if r["tags_json"] else [],
                    "notes": r["notes"] or "",
                    "is_favorite": bool(r["is_favorite"]),
                    "updated_at": r["updated_at"],
                }

            grp_rows = conn.execute("SELECT * FROM go2rtc_group_meta").fetchall()
            for r in grp_rows:
                groups[r["group_ip"]] = {
                    "group_ip": r["group_ip"],
                    "custom_name": r["custom_name"] or "",
                    "tags": json.loads(r["tags_json"]) if r["tags_json"] else [],
                    "notes": r["notes"] or "",
                    "is_favorite": bool(r["is_favorite"]),
                    "updated_at": r["updated_at"],
                }
        return {"cameras": cameras, "groups": groups}

    def save_go2rtc_camera_meta(
        self,
        stream_name: str,
        custom_title: Optional[str] = None,
        group_ip: Optional[str] = None,
        group_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
        is_favorite: Optional[bool] = None,
    ) -> dict:
        """Upsert metadata for an individual go2rtc stream."""
        stream_name = str(stream_name).strip()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM go2rtc_camera_meta WHERE stream_name = ?", (stream_name,)).fetchone()
            existing = dict(cur) if cur else {
                "custom_title": "",
                "group_ip": "",
                "group_name": "",
                "tags_json": "[]",
                "notes": "",
                "is_favorite": 0,
            }

            title = custom_title if custom_title is not None else existing.get("custom_title", "")
            g_ip = group_ip if group_ip is not None else existing.get("group_ip", "")
            g_name = group_name if group_name is not None else existing.get("group_name", "")
            t_json = json.dumps(tags, ensure_ascii=False) if tags is not None else existing.get("tags_json", "[]")
            nts = notes if notes is not None else existing.get("notes", "")
            fav = (1 if is_favorite else 0) if is_favorite is not None else existing.get("is_favorite", 0)

            conn.execute(
                """
                INSERT INTO go2rtc_camera_meta
                (stream_name, custom_title, group_ip, group_name, tags_json, notes, is_favorite, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(stream_name) DO UPDATE SET
                    custom_title = excluded.custom_title,
                    group_ip     = excluded.group_ip,
                    group_name   = excluded.group_name,
                    tags_json    = excluded.tags_json,
                    notes        = excluded.notes,
                    is_favorite  = excluded.is_favorite,
                    updated_at   = CURRENT_TIMESTAMP
                """,
                (stream_name, title, g_ip, g_name, t_json, nts, fav),
            )
            conn.commit()

        return {
            "stream_name": stream_name,
            "custom_title": title,
            "group_ip": g_ip,
            "group_name": g_name,
            "tags": json.loads(t_json) if isinstance(t_json, str) else t_json,
            "notes": nts,
            "is_favorite": bool(fav),
        }

    def save_go2rtc_group_meta(
        self,
        group_ip: str,
        custom_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
        is_favorite: Optional[bool] = None,
    ) -> dict:
        """Upsert metadata for an entire IP/location group."""
        group_ip = str(group_ip).strip()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM go2rtc_group_meta WHERE group_ip = ?", (group_ip,)).fetchone()
            existing = dict(cur) if cur else {
                "custom_name": "",
                "tags_json": "[]",
                "notes": "",
                "is_favorite": 0,
            }

            name = custom_name if custom_name is not None else existing.get("custom_name", "")
            t_json = json.dumps(tags, ensure_ascii=False) if tags is not None else existing.get("tags_json", "[]")
            nts = notes if notes is not None else existing.get("notes", "")
            fav = (1 if is_favorite else 0) if is_favorite is not None else existing.get("is_favorite", 0)

            conn.execute(
                """
                INSERT INTO go2rtc_group_meta
                (group_ip, custom_name, tags_json, notes, is_favorite, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(group_ip) DO UPDATE SET
                    custom_name  = excluded.custom_name,
                    tags_json    = excluded.tags_json,
                    notes        = excluded.notes,
                    is_favorite  = excluded.is_favorite,
                    updated_at   = CURRENT_TIMESTAMP
                """,
                (group_ip, name, t_json, nts, fav),
            )
            conn.commit()

        return {
            "group_ip": group_ip,
            "custom_name": name,
            "tags": json.loads(t_json) if isinstance(t_json, str) else t_json,
            "notes": nts,
            "is_favorite": bool(fav),
        }
