import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from ip2domain.cameras.scanner_v2.fast_preflight import run_fast_preflight, PreflightResult


@pytest.mark.anyio
async def test_fast_preflight_tr069_port():
    res = await run_fast_preflight("192.0.2.1", 7547)
    assert res.category == "router_tr069"
    assert res.brand == "TR-069 CWMP"
    assert res.target_protocols == ["router"]


@pytest.mark.anyio
async def test_fast_preflight_hikvision_detection():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "App-webs"}
    mock_resp.text = "<title>Hikvision</title>"

    with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
        res = await run_fast_preflight("192.0.2.2", 80)
        assert res.category == "cctv_hikvision"
        assert res.brand == "Hikvision"
        assert "hikvision" in res.target_protocols


@pytest.mark.anyio
async def test_fast_preflight_dahua_detection():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "DH-Webs", "www-authenticate": "Digest realm=\"DH_123\""}
    mock_resp.text = "<title>WEB SERVICE</title>"

    with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
        res = await run_fast_preflight("192.0.2.3", 80)
        assert res.category == "cctv_dahua"
        assert res.brand == "Dahua"
        assert "dahua" in res.target_protocols


@pytest.mark.anyio
async def test_fast_preflight_generic_web():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "nginx/1.18.0"}
    mock_resp.text = "<html><body>Welcome to Example Domain!</body></html>"

    with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
        res = await run_fast_preflight("192.0.2.4", 80)
        assert res.category == "generic_web"
        assert res.brand == "Nginx"
        assert res.target_protocols == ["generic"]


@pytest.mark.anyio
async def test_fast_preflight_inconclusive_auth_challenge():
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.headers = {"server": "Embedded HTTP Server", "www-authenticate": "Basic realm=\"Secure\""}
    mock_resp.text = "401 Unauthorized"

    with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
        res = await run_fast_preflight("192.0.2.5", 80)
        # Should be inconclusive so full probe suite runs and no device is dropped
        assert res.category == "inconclusive"
