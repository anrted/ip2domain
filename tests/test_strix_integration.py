import pytest
from starlette.testclient import TestClient
from ip2domain.web.app import app
from ip2domain.web.routers.common import strix_jobs, strix_results_cache


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("IP2DOMAIN_API_TOKEN", "test-secret-token")
    c = TestClient(app)
    c.headers.update({"X-API-Key": "test-secret-token"})
    return c


def test_strix_status_endpoint(client):
    response = client.get("/api/strix/status")
    assert response.status_code == 200
    data = response.json()
    assert "online" in data
    assert "url" in data


def test_strix_presets_endpoint(client):
    response = client.get("/api/strix/presets")
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert isinstance(data["results"], list)


def test_strix_scan_validation(client):
    # Empty target should fail
    response = client.post("/api/strix/scan", json={"targets": ""})
    assert response.status_code == 400

    # Invalid targets should fail
    response = client.post("/api/strix/scan", json={"targets": "not-an-ip-or-range"})
    assert response.status_code == 400


def test_strix_batch_scan_creates_job_and_tracks_status(client):
    targets = "127.0.0.1\n127.0.0.2"
    response = client.post("/api/strix/scan", json={"targets": targets, "ids": "p:top-150"})
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["total_targets"] == 2

    job_id = data["job_id"]
    status_resp = client.get(f"/api/strix/scan/{job_id}")
    assert status_resp.status_code == 200
    job = status_resp.json()
    assert job["job_id"] == job_id
    assert job["total_targets"] == 2
    assert "stage" in job

    # Test cancel
    cancel_resp = client.post(f"/api/strix/scan/{job_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["success"] is True


def test_strix_results_endpoints(client):
    strix_results_cache.clear()
    strix_results_cache.append({
        "ip": "192.168.1.100",
        "streams": [{"source": "rtsp://192.168.1.100/live", "width": 1920, "height": 1080}],
        "session_id": "test_sid"
    })
    
    get_resp = client.get("/api/strix/results")
    assert get_resp.status_code == 200
    assert len(get_resp.json()["results"]) == 1

    del_resp = client.delete("/api/strix/results")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    get_resp2 = client.get("/api/strix/results")
    assert get_resp2.status_code == 200
    assert len(get_resp2.json()["results"]) == 0


def test_strix_garbage_toggle(client):
    strix_results_cache.clear()
    strix_results_cache.append({
        "ip": "192.168.1.101",
        "streams": [{"source": "rtsp://192.168.1.101/live"}],
        "is_garbage": False
    })
    
    # Toggle to garbage
    resp = client.post("/api/strix/results/192.168.1.101/garbage", json={"is_garbage": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["is_garbage"] is True

    # Check cache and DB response
    get_resp = client.get("/api/strix/results")
    assert get_resp.status_code == 200
    results = get_resp.json()["results"]
    assert any(r["ip"] == "192.168.1.101" and r.get("is_garbage") is True for r in results)

    # Untoggle
    resp_un = client.post("/api/strix/results/192.168.1.101/garbage", json={"is_garbage": False})
    assert resp_un.status_code == 200
    assert resp_un.json()["is_garbage"] is False


def test_strix_db_targets_endpoint(client):
    """Test retrieving classified IP target presets from DB and go2rtc."""
    resp = client.get("/api/strix/targets/db_ips")
    assert resp.status_code == 200
    data = resp.json()
    assert "all_ips" in data
    assert "not_in_go2rtc" in data
    assert "in_go2rtc" in data
    assert "counts" in data
    assert isinstance(data["counts"]["total_saved"], int)
    assert isinstance(data["counts"]["not_in_go2rtc"], int)

