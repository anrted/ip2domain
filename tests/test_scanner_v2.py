"""Unit and integration tests for Camera Scanner v2."""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from ip2domain.cameras.scanner_v2.models import CameraResult, StreamInfo, ScanJob, DEFAULT_CREDENTIALS, CAMERA_PORTS_V2
from ip2domain.cameras.scanner_v2.engine import _parse_targets_streaming, create_job, get_job, cancel_job
from ip2domain.cameras.scanner_v2.stage1_sweep import check_tools
from ip2domain.core.storage import StorageManager
from ip2domain.web.app import app


def test_v2_models():
    """Test CameraResult and StreamInfo serialization."""
    stream = StreamInfo(url="rtsp://192.168.1.50:554/live", stream_type="rtsp", verified=True, width=1920, height=1080)
    assert stream.resolution == ""
    stream.resolution = f"{stream.width}x{stream.height}"
    assert stream.resolution == "1920x1080"
    sd = stream.to_dict()
    assert sd["url"] == "rtsp://192.168.1.50:554/live"
    assert sd["verified"] is True

    cam = CameraResult(
        ip="192.168.1.50",
        brand="Hikvision",
        model="DS-2CD2043G0-I",
        protocols=["onvif", "hikvision_isapi"],
        streams=[stream],
        open_ports=[80, 554],
    )
    cd = cam.to_dict()
    assert cd["ip"] == "192.168.1.50"
    assert cd["brand"] == "Hikvision"
    assert len(cd["streams"]) == 1
    assert cam.best_stream.url == "rtsp://192.168.1.50:554/live"


def test_v2_scan_job():
    """Test ScanJob progress tracking and cancellation."""
    job = create_job("test_job_1")
    assert job.status == "queued"
    assert not job.is_cancelled()
    job.add_log("Starting scan")
    assert len(job.logs) == 1
    assert "Starting scan" in job.logs[0]

    job_dict = job.to_dict()
    assert job_dict["job_id"] == "test_job_1"
    assert "stages" in job_dict
    assert "port_sweep" in job_dict["stages"]

    cancel_job("test_job_1")
    assert job.is_cancelled()


def test_target_parsing():
    """Test streaming target parser with single IPs, CIDRs, ranges."""
    text = """
    # Comments should be ignored
    192.168.1.1
    192.168.1.2
    10.0.0.1 - 10.0.0.3
    172.16.0.0/30
    192.168.1.1 # duplicate
    """
    targets = _parse_targets_streaming(text)
    assert "192.168.1.1" in targets
    assert "192.168.1.2" in targets
    assert "10.0.0.1" in targets
    assert "10.0.0.2" in targets
    assert "10.0.0.3" in targets
    # 172.16.0.0/30 has hosts .1 and .2
    assert "172.16.0.1" in targets
    assert "172.16.0.2" in targets
    # Check deduplication
    assert targets.count("192.168.1.1") == 1


def test_check_tools():
    """Test tool availability check."""
    tools = check_tools()
    assert isinstance(tools, dict)
    assert "masscan" in tools
    assert "nmap" in tools
    assert "ffmpeg" in tools
    assert "is_root" in tools


def test_storage_v2(tmp_path):
    """Test StorageManager v2 methods."""
    db_file = str(tmp_path / "test_v2.db")
    sm = StorageManager(db_path=db_file)
    sm.clear_v2_results()

    cam_data = {
        "ip": "10.10.10.10",
        "brand": "Dahua",
        "model": "IPC-HFW1230S",
        "serial": "DH1234567890",
        "protocols": ["dahua_cgi", "rtsp_direct"],
        "streams": [{"url": "rtsp://10.10.10.10:554/cam/realmonitor?channel=1&subtype=0", "type": "rtsp", "verified": False}],
        "open_ports": [80, 554, 37777],
    }
    sm.save_v2_result(cam_data)

    results = sm.get_v2_results()
    assert len(results) >= 1
    found = sm.get_v2_result("10.10.10.10")
    assert found is not None
    assert found["brand"] == "Dahua"
    assert found["in_go2rtc"] is False

    sm.mark_v2_result_go2rtc("10.10.10.10", True)
    found = sm.get_v2_result("10.10.10.10")
    assert found["in_go2rtc"] is True

    stats = sm.get_v2_stats()
    assert stats["total"] >= 1
    assert stats["by_brand"].get("Dahua", 0) >= 1

    sm.clear_v2_results()
    assert len(sm.get_v2_results()) == 0



def test_api_v2_tools():
    """Test /api/v2/tools endpoint."""
    client = TestClient(app)
    response = client.get("/api/v2/tools")
    # Authentication check
    assert response.status_code in (200, 303, 401)
    if response.status_code == 200:
        data = response.json()
        assert "masscan" in data


def test_api_v2_stats():
    """Test /api/v2/stats endpoint with mock auth."""
    client = TestClient(app)
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
        response = client.get("/api/v2/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_brand" in data


def test_v2_job_persistence_and_resume():
    """Test saving job, updating progress index, and retrieving active job for resume."""
    sm = StorageManager()
    test_jid = "v2_test_resume_99"

    sm.save_v2_job({
        "job_id": test_jid,
        "status": "running",
        "targets_str": "10.0.0.1/24",
        "current_index": 50,
        "total_targets": 254,
        "params": {"engine": "asyncio", "concurrency": 100},
        "logs": ["[Stage 1] In progress"],
    })

    # Query saved job
    saved = sm.get_v2_job(test_jid)
    assert saved is not None
    assert saved["job_id"] == test_jid
    assert saved["status"] == "running"
    assert saved["current_index"] == 50
    assert saved["targets_str"] == "10.0.0.1/24"

    # Update progress index
    sm.update_v2_job_progress(test_jid, current_index=120, progress_pct=48, stage="Sweep [120/254]", found_cameras=2)
    job = sm.get_v2_job(test_jid)
    assert job["current_index"] == 120
    assert job["found_cameras"] == 2

    # Mark completed
    sm.mark_v2_job_status(test_jid, "completed")
    job_done = sm.get_v2_job(test_jid)
    assert job_done["status"] == "completed"

    # No longer active
    active_after = sm.get_active_v2_job()
    assert active_after is None or active_after["job_id"] != test_jid

