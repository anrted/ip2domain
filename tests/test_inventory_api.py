import importlib
from unittest.mock import patch

from fastapi.testclient import TestClient

from ip2domain.scanning.policies import ScanConfig
from ip2domain.web.app import app

router = importlib.import_module("ip2domain.web.routers.inventory_scanner")


def test_inventory_requires_authentication_and_admin():
    client = TestClient(app)
    assert client.get("/api/scanner/v2/capabilities").status_code == 401
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"role": "user"}):
        assert client.get("/api/scanner/v2/capabilities").status_code == 403
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"role": "admin"}):
        response = client.get("/api/scanner/v2/capabilities")
        assert response.status_code == 200
        assert "rtsp" in response.json()["native"]["tcp"]
        assert "modbus-tcp" in response.json()["native"]["tcp"]
        assert "bacnet-ip" in response.json()["planned_native"]
        assert client.get("/scanner-v2").status_code == 200


def test_api_network_actions_are_opt_in(monkeypatch):
    monkeypatch.delenv("IP2DOMAIN_SCANNER_V2_ENABLED", raising=False)
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"role": "admin"}):
        response = TestClient(app).post("/api/scanner/v2/scans", json={"targets": "192.0.2.1", "authorized": True})
    assert response.status_code == 403


def test_api_validates_without_scanning_and_preserves_camera_api(monkeypatch):
    monkeypatch.setenv("IP2DOMAIN_SCANNER_V2_ENABLED", "1")
    launched = []
    monkeypatch.setattr(router, "_launch", lambda repository, identifier: launched.append(identifier))
    client = TestClient(app)
    with patch("ip2domain.web.app.auth_manager.get_session_user", return_value={"role": "admin"}):
        assert client.post("/api/scanner/v2/scans", json={"targets": "192.0.2.1"}).status_code == 422
        assert client.post("/api/scanner/v2/scans", json={
            "targets": "192.0.2.1", "profile": "deep_identification", "authorized": True,
        }).status_code == 422
        response = client.post("/api/scanner/v2/scans", json={
            "targets": "192.0.2.1", "tcp_ports": "1-65535", "authorized": True,
        })
        assert response.status_code == 200
        identifier = response.json()["id"]
        assert response.json()["total_endpoints"] == 65535
        assert launched == [identifier]
        assert client.get(f"/api/scanner/v2/scans/{identifier}").json()["status"] == "queued"
        assert client.get(f"/api/scanner/v2/scans/{identifier}/endpoints?limit=501").status_code == 422
        assert client.get(f"/api/scanner/v2/scans/{identifier}/export").status_code == 200
        assert client.post(f"/api/scanner/v2/scans/{identifier}/cancel", json={}).json()["status"] == "cancelled"
        assert client.get("/api/v2/tools").status_code == 200

        # Form checkbox "on" string values should normalize to bool
        resp_on = client.post("/api/scanner/v2/scans", json={
            "targets": "192.0.2.1", "tcp_ports": "80", "authorized": "on",
            "prioritize_base_ports": "on", "active_consent": "true",
        })
        assert resp_on.status_code == 200
