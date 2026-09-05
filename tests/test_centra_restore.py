import pytest
from fastapi.testclient import TestClient
from ip2domain.web.app import app
from ip2domain.web.routers.common import storage
from ip2domain.web.auth import AuthManager
from unittest.mock import patch
from pathlib import Path

def test_centra_discover_active_empty():
    with TestClient(app) as client:
        with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            res = client.get("/api/cameras/centra/discover/active")
            assert res.status_code == 200
            data = res.json()
            assert "jobs" in data
            assert isinstance(data["jobs"], list)

def test_centra_discover_active_with_job():
    with TestClient(app) as client:
        test_id = "test_active_jid_999"
        storage.upsert_job(
            job_id=test_id,
            job_type="centra_discovery",
            target="T-1-5",
            status="running",
            progress_pct=50,
            stage="Проверка камер",
            meta={"total": 10, "checked": 5, "found": 1, "speed": 2.0, "eta_seconds": 2.5}
        )
        try:
            with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
                res = client.get("/api/cameras/centra/discover/active")
                assert res.status_code == 200
                jobs = res.json()["jobs"]
                matching = [j for j in jobs if j.get("job_id") == test_id]
                assert len(matching) == 1
                assert matching[0]["status"] == "running"
                assert matching[0]["progress_pct"] == 50
                assert matching[0]["checked"] == 5
                assert matching[0]["found"] == 1

                res_single = client.get(f"/api/cameras/centra/discover/{test_id}")
                assert res_single.status_code == 200
                assert res_single.json()["job_id"] == test_id
        finally:
            with storage._get_connection() as conn:
                conn.execute("DELETE FROM active_jobs WHERE job_id = ?", (test_id,))
                conn.commit()

def test_centra_bundle_contains_restore():
    bundle_path = Path("ip2domain/web/static/cameras/centra.js")
    assert bundle_path.exists()
    content = bundle_path.read_text(encoding="utf-8")
    assert "restoreCentraScan" in content
    assert "window.restoreCentraScan = restoreCentraScan" in content
    assert "pollCentraDiscovery(jobIds, true)" in content
    assert "switchCameraTab" in content
    assert "cancelSingleCentraJob" in content
    assert "centra-job-cancel-btn" in content

def test_cancel_single_centra_queued_job():
    with TestClient(app) as client:
        test_id = "test_queue_cancel_1"
        storage.upsert_job(
            job_id=test_id,
            job_type="centra_discovery",
            target="T-1-5",
            status="queued",
            progress_pct=0,
            stage="В очереди",
            meta={"total": 10, "checked": 0, "found": 0}
        )
        try:
            with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
                res = client.post(f"/api/cameras/centra/discover/{test_id}/cancel")
                assert res.status_code == 200
                data = res.json()
                assert data["status"] == "cancelled"
                assert data["cancel_requested"] is True
                assert "Отменено в очереди" in data["stage"]

                # Verify get returns cancelled
                get_res = client.get(f"/api/cameras/centra/discover/{test_id}")
                assert get_res.status_code == 200
                assert get_res.json()["status"] == "cancelled"
        finally:
            with storage._get_connection() as conn:
                conn.execute("DELETE FROM active_jobs WHERE job_id = ?", (test_id,))
                conn.commit()

def test_cancel_single_centra_running_job():
    with TestClient(app) as client:
        test_id = "test_running_cancel_2"
        storage.upsert_job(
            job_id=test_id,
            job_type="centra_discovery",
            target="T-1-5",
            status="running",
            progress_pct=25,
            stage="Поиск камер",
            meta={"total": 20, "checked": 5, "found": 1}
        )
        try:
            with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
                res = client.post(f"/api/cameras/centra/discover/{test_id}/cancel")
                assert res.status_code == 200
                data = res.json()
                assert data["status"] == "cancelling"
                assert data["cancel_requested"] is True
                assert "Остановка" in data["stage"]
        finally:
            with storage._get_connection() as conn:
                conn.execute("DELETE FROM active_jobs WHERE job_id = ?", (test_id,))
                conn.commit()

def test_centra_screens_endpoint_and_types_count():
    storage.save_centra_cameras([
        {"id": "I-10-1", "title": "Домофон Советская 1", "camera_type": "I", "available": True},
        {"id": "H-20-1", "title": "Улица Кирова 10", "camera_type": "H", "available": True},
    ])
    storage.save_cameras("orion", [
        {
            "provider_id": "orion",
            "external_id": "999",
            "id": "999",
            "title": "Проспект Ленина 5",
            "address": "Проспект Ленина 5",
            "camera_type": "ORION",
            "available": True,
        }
    ])
    with TestClient(app) as client:
        with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            # 1. Total and types count
            res = client.get("/api/cameras/centra/screens")
            assert res.status_code == 200
            data = res.json()
            assert data["total"] == 3
            assert data["types_count"]["all"] == 3
            assert data["types_count"]["I"] == 1
            assert data["types_count"]["H"] == 1
            assert data["types_count"]["ORION"] == 1

            # 2. Filter by ORION type
            res_orion = client.get("/api/cameras/centra/screens?camera_type=ORION")
            assert res_orion.status_code == 200
            data_orion = res_orion.json()
            assert data_orion["total"] == 1
            assert data_orion["cameras"][0]["id"] == "ORION-999"

            # 3. Search case-insensitively
            res_search = client.get("/api/cameras/centra/screens?search=ленина")
            assert res_search.status_code == 200
            data_search = res_search.json()
            assert data_search["total"] == 1
            assert data_search["cameras"][0]["id"] == "ORION-999"

            # 4. Search Centra camera
            res_centra_search = client.get("/api/cameras/centra/screens?search=советская")
            assert res_centra_search.status_code == 200
            assert res_centra_search.json()["total"] == 1
            assert res_centra_search.json()["cameras"][0]["id"] == "I-10-1"

            # 5. Orion screenshot redirect
            res_screen = client.get("/api/cameras/centra/screens/ORION-999.jpg", follow_redirects=False)
            assert res_screen.status_code == 302
            assert "preview.jpg" in res_screen.headers["location"]

def test_centra_bundle_contains_screens_infinite_scroll_and_types():
    bundle_path = Path("ip2domain/web/static/cameras/centra.js")
    assert bundle_path.exists()
    content = bundle_path.read_text(encoding="utf-8")
    assert "populateCentraScreensTypes" in content
    assert "ensureCentraSentinelObserver" in content
    assert "getScreensTypeSelect" in content
    assert "getScreensSearchInput" in content
    assert "centra-screens-sentinel" in content

def test_centra_map_building_coordinates_and_clusterer_grouping():
    storage.save_centra_cameras([
        {"id": "I-50-1", "title": "Домофон Ленина 10", "building_id": 5001, "address": "ул. Ленина 10", "available": True},
        {"id": "H-50-2", "title": "Камера на доме Ленина 10", "building_id": 5001, "address": "ул. Ленина, 10", "available": True},
    ])
    storage.save_centra_coordinates("ул. Ленина 10", [53.75, 87.10])
    with TestClient(app) as client:
        with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            res = client.get("/api/cameras/centra?source=centra")
            assert res.status_code == 200
            cams = res.json()["cameras"]
            bld_cams = [c for c in cams if c.get("building_id") == 5001]
            assert len(bld_cams) == 2
            # Both cameras must have the exact same coordinates
            assert bld_cams[0].get("coordinates") == [53.75, 87.10]
            assert bld_cams[1].get("coordinates") == [53.75, 87.10]

    bundle_path = Path("ip2domain/web/static/cameras/centra.js")
    content = bundle_path.read_text(encoding="utf-8")
    assert "syncCentraClusterMode" in content
    assert "groupByCoordinates:" in content
    assert "hasBalloon: false" in content


