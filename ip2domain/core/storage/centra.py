"""Centra Gateway cameras, geocoding cache, discovery journals, YOLO people & ReID mixin."""
import json
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class CentraStorageMixin:
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
        # Compatibility bridge: Centra callers immediately populate generic catalog
        self.save_cameras("centra", cameras)

    def migrate_legacy_centra_catalog(self) -> int:
        """Idempotently project legacy Centra rows into the provider-neutral catalog."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT camera_json FROM centra_cameras legacy
                WHERE NOT EXISTS (
                    SELECT 1 FROM camera_catalog catalog
                    WHERE catalog.provider_id = 'centra' AND
                          catalog.external_id = legacy.camera_id
                )
            """).fetchall()
        cameras = [json.loads(row["camera_json"]) for row in rows]
        self.save_cameras("centra", cameras)
        return len(cameras)

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

    def get_centra_camera(self, camera_id: str) -> Optional[Dict[str, any]]:
        camera_id = camera_id.strip().upper()
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT camera_json, first_seen, updated_at FROM centra_cameras
                WHERE UPPER(camera_id) = ?
            """, (camera_id,)).fetchone()
        if not row:
            return None
        camera = json.loads(row["camera_json"])
        camera["first_seen"] = row["first_seen"]
        camera["updated_at"] = row["updated_at"]
        return camera

    def list_centra_cameras_page(self, offset: int = 0, limit: int = 100,
                                 camera_type: str = "", search: str = "") -> Dict[str, any]:
        conditions = ["COALESCE(json_extract(camera_json, '$.available'), 1) = 1"]
        params = []
        if camera_type:
            conditions.append("UPPER(camera_id) LIKE ?")
            params.append(f"{camera_type.upper()}-%")
        if search.strip():
            conditions.append("CASEFOLD_CONTAINS(camera_id || ' ' || title, ?) = 1")
            params.append(search.strip())
        where = f"WHERE {' AND '.join(conditions)}"
        with self._get_connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM centra_cameras {where}", params).fetchone()[0]
            rows = conn.execute(f"""
                SELECT camera_json, first_seen, updated_at FROM centra_cameras
                {where}
                ORDER BY title COLLATE NATURAL_NOCASE, camera_id COLLATE NATURAL_NOCASE
                LIMIT ? OFFSET ?
            """, (*params, limit, offset)).fetchall()
        cameras = []
        for row in rows:
            camera = json.loads(row["camera_json"])
            camera["first_seen"] = row["first_seen"]
            camera["updated_at"] = row["updated_at"]
            cameras.append(camera)
        return {"cameras": cameras, "total": total}

    def clear_centra_cameras(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM centra_cameras")
            conn.execute("DELETE FROM centra_scan_checks")
            conn.execute("DELETE FROM camera_catalog WHERE provider_id = 'centra'")
            conn.commit()
            return cursor.rowcount

    def save_centra_coordinates(self, address: str, coordinates: List[float]) -> None:
        address = address.strip()
        if not address or len(coordinates) != 2:
            return
        latitude, longitude = coordinates
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO centra_geocode_cache (address, latitude, longitude, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(address) DO UPDATE SET
                    latitude=excluded.latitude,
                    longitude=excluded.longitude,
                    updated_at=CURRENT_TIMESTAMP
            """, (address, float(latitude), float(longitude)))
            conn.commit()

    def get_centra_coordinates(self, addresses: List[str]) -> Dict[str, List[float]]:
        unique = [item.strip() for item in dict.fromkeys(addresses) if item and item.strip()]
        if not unique:
            return {}
        result = {}
        with self._get_connection() as conn:
            for index in range(0, len(unique), 900):
                chunk = unique[index:index + 900]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT address, latitude, longitude FROM centra_geocode_cache WHERE address IN ({placeholders})",
                    chunk,
                ).fetchall()
                for row in rows:
                    result[row["address"]] = [float(row["latitude"]), float(row["longitude"])]
        return result

    def save_centra_scan_checks(self, checks: List[Dict[str, any]]) -> None:
        rows = []
        for item in checks:
            camera_id = str(item.get("camera_id") or "").strip().upper()
            if not camera_id:
                continue
            rows.append((camera_id, str(item.get("camera_type") or "").strip().upper(),
                         int(item.get("building_id") or 0), int(item.get("entrance") or 0),
                         int(bool(item.get("found")))))
        if not rows:
            return
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO centra_scan_checks
                    (camera_id, camera_type, building_id, entrance, found, checked_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(camera_id) DO UPDATE SET
                    found=excluded.found,
                    checked_at=CURRENT_TIMESTAMP
            """, rows)
            conn.commit()

    def get_centra_checked_ids(self, camera_type: str, start_id: int, end_id: int,
                               entrance_start: int, entrance_end: int) -> List[str]:
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT camera_id FROM centra_scan_checks
                WHERE camera_type = ? AND building_id BETWEEN ? AND ? AND entrance BETWEEN ? AND ?
            """, (camera_type.strip().upper(), start_id, end_id, entrance_start, entrance_end)).fetchall()
        return [row["camera_id"] for row in rows]

    def save_centra_person_result(self, result: Dict[str, any]) -> None:
        camera_id = str(result.get("camera_id") or result.get("id") or "").strip().upper()
        if not camera_id:
            return
        camera_type = str(result.get("camera_type") or camera_id.split("-", 1)[0]).strip().upper()
        people_count = int(result.get("people_count") or 0)
        confidence = float(result.get("confidence") or 0.0)
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO centra_person_results
                    (camera_id, camera_type, people_count, confidence, result_json, detected_at, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(camera_id) DO UPDATE SET
                    camera_type=excluded.camera_type,
                    people_count=excluded.people_count,
                    confidence=excluded.confidence,
                    result_json=excluded.result_json,
                    detected_at=CURRENT_TIMESTAMP,
                    updated_at=CURRENT_TIMESTAMP
            """, (camera_id, camera_type, people_count, confidence, json.dumps(result, ensure_ascii=False)))
            conn.commit()

    def list_centra_person_results(self, offset: int = 0, limit: int = 100,
                                   camera_type: str = "", search: str = "") -> Dict[str, any]:
        conditions = ["people_count > 0"]
        params = []
        if camera_type:
            conditions.append("camera_type = ?")
            params.append(camera_type.upper())
        if search.strip():
            conditions.append("CASEFOLD_CONTAINS(camera_id || ' ' || json_extract(result_json, '$.title') || ' ' || json_extract(result_json, '$.address'), ?) = 1")
            params.append(search.strip())
        where = f"WHERE {' AND '.join(conditions)}"
        with self._get_connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM centra_person_results {where}", params).fetchone()[0]
            rows = conn.execute(f"""
                SELECT result_json, detected_at, updated_at FROM centra_person_results
                {where}
                ORDER BY detected_at DESC, camera_id COLLATE NATURAL_NOCASE
                LIMIT ? OFFSET ?
            """, (*params, limit, offset)).fetchall()
        cameras = []
        for row in rows:
            camera = json.loads(row["result_json"])
            camera["detected_at"] = row["detected_at"]
            camera["updated_at"] = row["updated_at"]
            cameras.append(camera)
        return {"cameras": cameras, "total": total}

    def save_centra_reid_states(self, states: Dict[str, dict]) -> None:
        if not states:
            return
        rows = [(person_id, json.dumps(state, ensure_ascii=False), float(state.get("last_seen") or 0))
                for person_id, state in states.items()]
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO centra_reid_identities (person_id, state_json, last_seen, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(person_id) DO UPDATE SET
                    state_json=excluded.state_json,
                    last_seen=excluded.last_seen,
                    updated_at=CURRENT_TIMESTAMP
            """, rows)
            conn.commit()

    def load_centra_reid_states(self, ttl: int) -> Dict[str, dict]:
        import time
        cutoff = time.time() - ttl
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT person_id, state_json FROM centra_reid_identities WHERE last_seen >= ?",
                (cutoff,),
            ).fetchall()
        return {row["person_id"]: json.loads(row["state_json"]) for row in rows}

    def get_centra_reid_state(self, person_id: str, ttl: int) -> Optional[dict]:
        import time
        cutoff = time.time() - ttl
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT state_json FROM centra_reid_identities WHERE person_id = ? AND last_seen >= ?",
                (person_id.strip().lower(), cutoff),
            ).fetchone()
        return json.loads(row["state_json"]) if row else None

    def clear_centra_reid_states(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM centra_reid_identities")
            conn.commit()
            return cursor.rowcount
