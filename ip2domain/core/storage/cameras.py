"""IP Camera network devices and provider-neutral Camera Catalog mixin."""
import json
import logging
import uuid
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class CamerasStorageMixin:
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

    def get_camera_device(self, target: str) -> Optional[Dict[str, any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT device_json, first_seen, updated_at FROM camera_devices WHERE target = ?",
                               (target.strip(),)).fetchone()
        if not row:
            return None
        device = json.loads(row["device_json"])
        device["first_seen"], device["updated_at"] = row["first_seen"], row["updated_at"]
        return device

    def clear_camera_devices(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM camera_devices")
            conn.commit()
            return cursor.rowcount

    @staticmethod
    def camera_uid(provider_id: str, external_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL,
                              f"ip2domain:camera:{provider_id.strip().lower()}:{external_id.strip()}"))

    def save_cameras(self, provider_id: str, cameras: List[Dict[str, any]]) -> None:
        provider_id = provider_id.strip().lower()
        if not provider_id:
            raise ValueError("provider_id is required")
        rows = []
        for camera in cameras:
            external_id = str(camera.get("external_id") or camera.get("id") or "").strip()
            if not external_id:
                continue
            normalized = dict(camera)
            normalized.update(provider_id=provider_id, external_id=external_id,
                              id=external_id, uid=self.camera_uid(provider_id, external_id))
            coordinates = normalized.get("coordinates") or [None, None]
            latitude = normalized.get("latitude", coordinates[0] if len(coordinates) > 0 else None)
            longitude = normalized.get("longitude", coordinates[1] if len(coordinates) > 1 else None)
            rows.append((normalized["uid"], provider_id, external_id,
                         str(normalized.get("title") or ""), str(normalized.get("address") or ""),
                         str(normalized.get("camera_type") or ""), int(bool(normalized.get("available", True))),
                         latitude, longitude, json.dumps(normalized, ensure_ascii=False)))
        if not rows:
            return
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO camera_catalog
                    (camera_uid, provider_id, external_id, title, address, camera_type,
                     available, latitude, longitude, camera_json, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(provider_id, external_id) DO UPDATE SET
                    title=excluded.title, address=excluded.address, camera_type=excluded.camera_type,
                    available=excluded.available, latitude=excluded.latitude, longitude=excluded.longitude,
                    camera_json=excluded.camera_json, last_seen=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
            """, rows)
            conn.commit()

    def get_camera(self, provider_id: str, external_id: str) -> Optional[Dict[str, any]]:
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT camera_json, camera_uid, first_seen, last_seen, updated_at
                FROM camera_catalog WHERE provider_id = ? AND external_id = ?
            """, (provider_id.strip().lower(), external_id.strip())).fetchone()
        if not row:
            return None
        camera = json.loads(row["camera_json"])
        camera.update(uid=row["camera_uid"], first_seen=row["first_seen"],
                      last_seen=row["last_seen"], updated_at=row["updated_at"])
        return camera

    def list_cameras(self, offset: int = 0, limit: int = 100, provider_id: str = "",
                     camera_type: str = "", search: str = "", available_only: bool = True) -> Dict[str, any]:
        conditions, params = [], []
        if available_only:
            conditions.append("available = 1")
        if provider_id:
            conditions.append("provider_id = ?")
            params.append(provider_id.strip().lower())
        if camera_type:
            conditions.append("UPPER(camera_type) = ?")
            params.append(camera_type.upper())
        if search.strip():
            conditions.append("CASEFOLD_CONTAINS(external_id || ' ' || title || ' ' || address, ?) = 1")
            params.append(search.strip())
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._get_connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM camera_catalog {where}", params).fetchone()[0]
            rows = conn.execute(f"""
                SELECT camera_json, camera_uid, first_seen, last_seen, updated_at
                FROM camera_catalog {where}
                ORDER BY title COLLATE NATURAL_NOCASE, external_id COLLATE NATURAL_NOCASE
                LIMIT ? OFFSET ?
            """, (*params, limit, offset)).fetchall()
        cameras = []
        for row in rows:
            camera = json.loads(row["camera_json"])
            camera.update(uid=row["camera_uid"], first_seen=row["first_seen"],
                          last_seen=row["last_seen"], updated_at=row["updated_at"])
            cameras.append(camera)
        return {"cameras": cameras, "total": total, "offset": offset, "limit": limit,
                "has_more": offset + len(cameras) < total}

    def save_camera_snapshot(self, snapshot_id: str, camera_uid: str, source_kind: str,
                             storage_key: Optional[str], content_type: Optional[str],
                             byte_size: Optional[int], checksum: Optional[str],
                             status: str, error: Optional[str] = None,
                             metadata: Optional[Dict[str, any]] = None) -> Dict[str, any]:
        row = {
            "snapshot_id": snapshot_id,
            "camera_uid": camera_uid,
            "source_kind": source_kind,
            "storage_key": storage_key,
            "content_type": content_type,
            "byte_size": byte_size,
            "checksum": checksum,
            "status": status,
            "error": error,
            "metadata_json": json.dumps(metadata or {}, ensure_ascii=False),
        }
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO camera_snapshots
                    (snapshot_id, camera_uid, source_kind, storage_key, content_type,
                     byte_size, checksum, status, error, metadata_json, captured_at)
                VALUES
                    (:snapshot_id, :camera_uid, :source_kind, :storage_key, :content_type,
                     :byte_size, :checksum, :status, :error, :metadata_json, CURRENT_TIMESTAMP)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    source_kind=excluded.source_kind,
                    storage_key=excluded.storage_key,
                    content_type=excluded.content_type,
                    byte_size=excluded.byte_size,
                    checksum=excluded.checksum,
                    status=excluded.status,
                    error=excluded.error,
                    metadata_json=excluded.metadata_json,
                    captured_at=CURRENT_TIMESTAMP
            """, row)
            conn.commit()
        return self.get_camera_snapshot(snapshot_id) or row

    def get_camera_snapshot(self, snapshot_id: str) -> Optional[Dict[str, any]]:
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT snapshot_id, camera_uid, captured_at, source_kind, storage_key,
                       content_type, byte_size, checksum, status, error, metadata_json
                FROM camera_snapshots WHERE snapshot_id = ?
            """, (snapshot_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json", "{}") or "{}")
        return item

    def save_camera_analysis(self, result_id: str, camera_uid: str, analysis_type: str,
                             result: Dict[str, any], snapshot_id: Optional[str] = None,
                             model_name: Optional[str] = None) -> Dict[str, any]:
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO camera_analysis_results
                    (result_id, camera_uid, snapshot_id, analysis_type, model_name, result_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(result_id) DO UPDATE SET
                    snapshot_id=excluded.snapshot_id,
                    analysis_type=excluded.analysis_type,
                    model_name=excluded.model_name,
                    result_json=excluded.result_json,
                    created_at=CURRENT_TIMESTAMP
            """, (result_id, camera_uid, snapshot_id, analysis_type, model_name,
                  json.dumps(result, ensure_ascii=False)))
            conn.commit()
        return {
            "result_id": result_id, "camera_uid": camera_uid, "snapshot_id": snapshot_id,
            "analysis_type": analysis_type, "model_name": model_name, "result": result,
        }

    def list_camera_analysis(self, camera_uid: str, analysis_type: str = "",
                             limit: int = 100) -> List[Dict[str, any]]:
        conditions = ["camera_uid = ?"]
        params = [camera_uid]
        if analysis_type:
            conditions.append("analysis_type = ?")
            params.append(analysis_type)
        with self._get_connection() as conn:
            rows = conn.execute(f"""
                SELECT result_id, camera_uid, snapshot_id, analysis_type, model_name,
                       result_json, created_at
                FROM camera_analysis_results
                WHERE {' AND '.join(conditions)}
                ORDER BY created_at DESC
                LIMIT ?
            """, (*params, limit)).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["result"] = json.loads(item.pop("result_json", "{}") or "{}")
            results.append(item)
        return results
