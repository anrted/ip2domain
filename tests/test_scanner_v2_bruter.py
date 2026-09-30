"""Unit tests for scanner_v2 401 auth filtering, export, and RTSP bruter module."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from ip2domain.cameras.scanner_v2.bruter import RtspBruteManager
from ip2domain.core.storage import StorageManager
from ip2domain.web.app import app


@pytest.fixture
def tmp_storage(tmp_path):
    db_path = tmp_path / "test.db"
    return StorageManager(db_path=db_path)


def test_storage_auth_status_filtering(tmp_storage):
    # Insert 1 camera with auth_required=True
    tmp_storage.save_v2_result({
        "ip": "10.0.0.1",
        "brand": "Hikvision",
        "rtsp_port": 554,
        "auth_required": True,
        "credentials": {},
        "streams": [{"url": "rtsp://10.0.0.1:554/live", "verified": False}],
    })

    # Insert 1 camera with auth_required=False and credentials
    tmp_storage.save_v2_result({
        "ip": "10.0.0.2",
        "brand": "Dahua",
        "rtsp_port": 554,
        "auth_required": False,
        "credentials": {"user": "admin", "password": "admin123"},
        "streams": [{"url": "rtsp://admin:admin123@10.0.0.2:554/cam/realmonitor", "verified": True}],
    })

    all_res = tmp_storage.get_v2_results(auth_status="all")
    assert len(all_res) == 2

    locked_res = tmp_storage.get_v2_results(auth_status="401")
    assert len(locked_res) == 1
    assert locked_res[0]["ip"] == "10.0.0.1"
    assert locked_res[0]["auth_required"] is True

    open_res = tmp_storage.get_v2_results(auth_status="open")
    assert len(open_res) == 1
    assert open_res[0]["ip"] == "10.0.0.2"
    assert open_res[0]["auth_required"] is False


def test_api_export_401(tmp_storage):
    tmp_storage.save_v2_result({
        "ip": "192.168.1.50",
        "brand": "Hikvision",
        "rtsp_port": 554,
        "auth_required": True,
        "streams": [],
    })
    tmp_storage.save_v2_result({
        "ip": "192.168.1.60",
        "brand": "OpenCam",
        "rtsp_port": 554,
        "auth_required": False,
        "streams": [{"screenshot": "/v2_captures/snap.jpg"}],
    })

    client = TestClient(app)
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}), \
         patch("ip2domain.web.routers.scanner_v2.storage", tmp_storage):
        resp = client.get("/api/v2/export/401")
        assert resp.status_code == 200
        content = resp.text
        assert "192.168.1.50:554" in content
        assert "192.168.1.60" not in content

        # Test CSV format
        resp_csv = client.get("/api/v2/export/401?format=csv")
        assert resp_csv.status_code == 200
        assert "ip,port,brand,model,city" in resp_csv.text
        assert "192.168.1.50,554,Hikvision" in resp_csv.text


def test_rtsp_brute_manager_parsing_and_persistence(tmp_storage, tmp_path):
    mgr = RtspBruteManager(
        script_path=tmp_path / "dummy_script.py",
        python_path=Path("/bin/echo"),
    )
    (tmp_path / "dummy_script.py").write_text("# dummy", encoding="utf-8")

    # Mock storage
    tmp_storage.save_v2_result({
        "ip": "10.0.0.5",
        "brand": "Hikvision",
        "rtsp_port": 554,
        "auth_required": True,
        "streams": [{"url": "rtsp://10.0.0.5:554/Streaming/Channels/101"}],
    })

    async def _run():
        # Test cracked handler with capture_dir=None to prevent real network I/O
        await mgr._on_camera_cracked(
            tgt="10.0.0.5:554",
            user="admin",
            password="password123",
            storage=tmp_storage,
            capture_dir=None,
            no_auth=False,
        )

    asyncio.run(_run())

    assert mgr.cracked_count == 1
    assert len(mgr.cracked_cameras) == 1
    assert mgr.cracked_cameras[0]["user"] == "admin"
    assert mgr.cracked_cameras[0]["password"] == "password123"

    updated_cam = tmp_storage.get_v2_result("10.0.0.5")
    assert updated_cam is not None
    assert updated_cam["auth_required"] is False
    assert updated_cam["credentials"] == {"user": "admin", "password": "password123"}
    assert "admin:password123@" in updated_cam["streams"][0]["url"]


def test_api_bruter_endpoints(tmp_storage):
    client = TestClient(app)
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}), \
         patch("ip2domain.web.routers.scanner_v2.storage", tmp_storage):
        status_resp = client.get("/api/v2/bruter/status")
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert "status" in status_data
        assert "cracked_count" in status_data

        stop_resp = client.post("/api/v2/bruter/stop")
        assert stop_resp.status_code == 200
