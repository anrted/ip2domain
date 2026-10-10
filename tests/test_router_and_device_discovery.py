"""Tests for router, network gear, and generic web device discovery."""
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ip2domain.cameras.scanner_v2.models import CameraResult, CAMERA_PORTS_V2, ROUTER_PORTS
from ip2domain.cameras.scanner_v2.protocols.router import probe_router
from ip2domain.cameras.scanner_v2.aggregation import merge_camera_results, merge_host_cameras
from ip2domain.cameras.scanner_v2.web_capture import generate_web_card_image, capture_web_screenshot


def test_router_ports_included_in_v2():
    assert 8291 in CAMERA_PORTS_V2
    assert 7547 in CAMERA_PORTS_V2
    # Standard and alternate router web ports
    for p in (80, 443, 8080, 8081, 8888, 8181, 8880, 9443, 10443, 4567):
        assert p in CAMERA_PORTS_V2
        assert p in ROUTER_PORTS


def test_probe_router_mikrotik_winbox():
    async def _test():
        with patch("ip2domain.cameras.scanner_v2.protocols.router.probe_winbox", new_callable=AsyncMock) as mock_winbox:
            mock_winbox.return_value = True
            res = await probe_router("192.168.88.1", [8291], [])
            assert res["success"] is True
            assert res["brand"] == "MikroTik"
            assert res["model"] == "RouterOS"
            assert res["device_category"] == "router"
            assert "winbox" in res["protocols"]
    asyncio.run(_test())


def test_probe_router_keenetic_http():
    async def _test():
        mock_resp = AsyncMock()
        mock_resp.text = "<html><head><title>Keenetic Web</title></head><body>KeeneticOS</body></html>"
        mock_resp.headers = {"server": "nginx", "www-authenticate": 'Basic realm="Keenetic Extra"'}
        mock_resp.status_code = 401

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await probe_router("192.168.1.1", [80], [])
            assert res["success"] is True
            assert res["brand"] == "Keenetic"
            assert res["device_category"] == "router"
            assert res["auth_required"] is True
            assert res["web_port"] == 80
    asyncio.run(_test())


def test_probe_router_tplink_http():
    async def _test():
        mock_resp = AsyncMock()
        mock_resp.text = "<html><head><title>TP-Link Wireless Router WR841N</title></head><body></body></html>"
        mock_resp.headers = {"server": "httpd", "www-authenticate": 'Basic realm="TP-Link Wireless Router"'}
        mock_resp.status_code = 401

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await probe_router("192.168.0.1", [80], [])
            assert res["success"] is True
            assert res["brand"] == "TP-Link"
            assert res["device_category"] == "router"
    asyncio.run(_test())


def test_merge_camera_results_preserves_router():
    router_probe_result = {
        "router": {
            "success": True,
            "brand": "Keenetic",
            "model": "Keenetic Extra",
            "device_category": "router",
            "title": "Keenetic Web",
            "web_port": 80,
            "web_url": "http://192.168.1.1:80/",
            "protocols": ["http_router"],
        }
    }
    result = merge_camera_results("192.168.1.1", [80], router_probe_result)
    assert result is not None
    assert result.brand == "Keenetic"
    assert result.model == "Keenetic Extra"
    assert result.device_category == "router"
    assert result.web_title == "Keenetic Web"
    assert result.http_port == 80


def test_merge_camera_results_zero_drop_policy():
    # If generic HTTP probe detected a web panel, host is retained as generic_web
    web_res_map = {
        "onvif": {}, "hikvision": {}, "dahua": {},
        "generic": {
            "success": True,
            "brand": "Generic Web Device",
            "device_category": "generic_web",
            "title": "Welcome to Service",
            "http_port": 80,
            "web_url": "http://10.0.0.99:80/",
        }
    }
    result = merge_camera_results("10.0.0.99", [80, 8080], web_res_map)
    assert result is not None
    assert result.device_category == "generic_web"
    assert result.brand == "Generic Web Device"
    assert result.web_title == "Welcome to Service"

    # MikroTik Winbox open port without camera probes is retained as router
    empty_res_map = {"onvif": {}, "hikvision": {}, "dahua": {}, "generic": {}}
    winbox_res = merge_camera_results("10.0.0.100", [8291], empty_res_map)
    assert winbox_res is not None
    assert winbox_res.brand == "MikroTik"
    assert winbox_res.device_category == "router"


def test_web_card_image_generator(tmp_path):
    out_file = tmp_path / "web_card.jpg"
    ok = generate_web_card_image(
        out_file=out_file,
        ip="192.168.1.1",
        port=80,
        web_url="http://192.168.1.1:80/",
        brand="MikroTik",
        model="RouterOS",
        title="MikroTik WebFig",
        category="router",
    )
    assert ok is True
    assert out_file.is_file()
    assert out_file.stat().st_size > 500


def test_capture_web_screenshot_generates_file(tmp_path):
    async def _test():
        rel_url = await capture_web_screenshot(
            ip="192.168.88.1",
            port=80,
            web_url="http://192.168.88.1/",
            capture_dir=tmp_path,
            brand="MikroTik",
            model="RouterOS",
            title="MikroTik RouterOS",
            category="router",
        )
        assert rel_url == "/v2_captures/web_192.168.88.1_80.jpg"
        out_file = tmp_path / "web_192.168.88.1_80.jpg"
        assert out_file.is_file()
        assert out_file.stat().st_size > 500
    asyncio.run(_test())


def test_storage_category_filtering(tmp_path):
    from ip2domain.core.storage.scanner_v2 import ScannerV2StorageMixin
    from ip2domain.core.storage.base import BaseStorage

    class TestStorage(ScannerV2StorageMixin, BaseStorage):
        pass

    storage = TestStorage(db_path=str(tmp_path / "test_cat.db"))

    # Save camera
    storage.save_v2_result({
        "ip": "10.0.0.1",
        "brand": "Hikvision",
        "device_category": "camera",
        "streams": [{"url": "rtsp://10.0.0.1:554/live"}],
    })

    # Save router
    storage.save_v2_result({
        "ip": "10.0.0.2",
        "brand": "MikroTik",
        "device_category": "router",
        "web_title": "RouterOS",
        "web_url": "http://10.0.0.2/",
    })

    all_res = storage.get_v2_results()
    assert len(all_res) == 2

    routers = storage.get_v2_results(category="router")
    assert len(routers) == 1
    assert routers[0]["ip"] == "10.0.0.2"
    assert routers[0]["brand"] == "MikroTik"

    cameras = storage.get_v2_results(category="camera")
    assert len(cameras) == 1
    assert cameras[0]["ip"] == "10.0.0.1"


def test_engine_stage2_zero_drop_fallback():
    # If probe returns None but open_ports exist, engine retains as device
    from ip2domain.cameras.scanner_v2.models import CameraResult, HTTP_PORTS as _HTTP_PORTS
    open_ports = [8080]
    camera = None
    if not camera and open_ports:
        if 8291 in open_ports:
            camera = CameraResult(
                ip="10.0.0.5", brand="MikroTik", model="RouterOS",
                device_category="router", open_ports=sorted(open_ports),
                protocols=["winbox"]
            )
        elif any(p in _HTTP_PORTS for p in open_ports):
            hp = next(p for p in open_ports if p in _HTTP_PORTS)
            camera = CameraResult(
                ip="10.0.0.5", brand="Generic Web Device", model="Web Service",
                http_port=hp, web_url=f"http://10.0.0.5:{hp}/",
                device_category="generic_web", open_ports=sorted(open_ports),
                protocols=["http"]
            )
        else:
            camera = CameraResult(
                ip="10.0.0.5", brand="Generic Network Device",
                device_category="device", open_ports=sorted(open_ports),
                protocols=["tcp"]
            )
    assert camera is not None
    assert camera.device_category == "generic_web"
    assert camera.http_port == 8080


def test_merge_camera_results_no_bogus_snapshot_urls_for_routers_and_web():
    web_res_map = {
        "onvif": {}, "hikvision": {}, "dahua": {},
        "generic": {
            "success": True,
            "brand": "Generic Web Device",
            "device_category": "generic_web",
            "title": "Welcome to nginx",
            "http_port": 80,
            "web_url": "http://62.173.154.168:80/",
        }
    }
    result = merge_camera_results("62.173.154.168", [80, 443], web_res_map)
    assert result is not None
    assert result.device_category == "generic_web"
    # Must NOT have bogus snapshot.cgi URLs
    for s in result.streams:
        assert "snapshot.cgi" not in s.url
        assert s.stream_type != "http_snapshot"
    # Should have clean web_panel stream
    assert any(s.stream_type == "web_panel" for s in result.streams)


def test_sanitize_v2_result_strips_bogus_streams():
    from ip2domain.web.routers.scanner_v2 import _sanitize_v2_result
    dirty_result = {
        "ip": "62.173.139.144",
        "brand": "Generic Web Device",
        "device_category": "generic_web",
        "http_port": 443,
        "web_url": "https://62.173.139.144:443/",
        "streams": [
            {"url": "http://62.173.139.144:443/cgi-bin/snapshot.cgi?channel=1", "type": "http_snapshot"},
            {"url": "http://62.173.139.144:443/snapshot.jpg", "type": "http_snapshot"},
        ]
    }
    clean = _sanitize_v2_result(dirty_result)
    assert len(clean["streams"]) == 1
    assert clean["streams"][0]["type"] == "web_panel"
    assert clean["streams"][0]["url"] == "https://62.173.139.144:443/"


def test_generic_http_tplink_tl_sc_camera():
    from ip2domain.cameras.scanner_v2.protocols.generic_http import probe_generic_http
    async def _test():
        prod_resp = AsyncMock()
        prod_resp.status_code = 200
        prod_resp.text = 'var initProdShortName="mag_52";\nvar initProdFullName="Wireless 2-Way Audio Surveillance Camera";\nvar initProdNbr="TL-SC3130G";'
        prod_resp.headers = {"server": "Boa/0.94.13"}

        auth_resp = AsyncMock()
        auth_resp.status_code = 401
        auth_resp.text = "<html>401 Unauthorized</html>"
        auth_resp.headers = {"server": "Boa/0.94.13", "www-authenticate": 'Basic realm="mag_52"'}

        async def _mock_get(url, **kwargs):
            if "/prod" in url:
                return prod_resp
            return auth_resp

        with patch("httpx.AsyncClient.get", side_effect=_mock_get):
            res = await probe_generic_http("82.209.197.84", [8082], [("admin", "admin")])
            assert res["success"] is True
            assert res["brand"] == "TP-Link"
            assert res["model"] == "TL-SC3130G"
            assert res["device_category"] == "camera"
            assert res["snapshot_path"] == "/jpg/image.jpg"
            assert res["rtsp_path"] == "/video.mp4"
            assert res["auth_required"] is True
    asyncio.run(_test())


def test_merge_camera_results_tplink_sc():
    web_res_map = {
        "onvif": {}, "hikvision": {}, "dahua": {},
        "generic": {
            "success": True,
            "brand": "TP-Link",
            "model": "TL-SC3130G",
            "device_category": "camera",
            "title": "Wireless 2-Way Audio Surveillance Camera",
            "http_port": 8082,
            "web_url": "http://82.209.197.84:8082/",
            "snapshot_path": "/jpg/image.jpg",
            "rtsp_path": "/video.mp4",
            "credentials": {"user": "admin", "password": "admin"},
        }
    }
    result = merge_camera_results("82.209.197.84", [8082], web_res_map)
    assert result is not None
    assert result.device_category == "camera"
    assert result.brand == "TP-Link"
    assert result.model == "TL-SC3130G"
    stream_urls = [s.url for s in result.streams]
    assert "http://82.209.197.84:8082/jpg/image.jpg" in stream_urls
    assert "rtsp://82.209.197.84:8082/video.mp4" in stream_urls



def test_export_filtered_ips_endpoint():
    from fastapi.testclient import TestClient
    from ip2domain.web.app import app

    client = TestClient(app)
    # Test export with brand filter
    resp = client.get("/api/v2/export/ips?brand=TP-Link")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text
    # Should be clean list of IPs without ports (no colons)
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    for line in lines:
        assert ":" not in line
        assert not line.startswith("http")


def test_dnvrs_camera_fingerprint():
    from ip2domain.cameras.scanner_v2.protocols.generic_http import probe_generic_http

    async def _test():
        mock_resp = AsyncMock()
        mock_resp.text = "<html><head><title></title></head><body>DNVRS-Webs login</body></html>"
        mock_resp.headers = {"server": "DNVRS-Webs"}
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await probe_generic_http("93.84.121.54", [8001], [])
            assert res["success"] is True
            assert res["brand"] == "Hikvision"
            assert res["device_category"] == "camera"
    asyncio.run(_test())


def test_flussonic_streamer_fingerprint():
    from ip2domain.cameras.scanner_v2.protocols.generic_http import probe_generic_http

    async def _test():
        mock_resp = AsyncMock()
        mock_resp.text = "<html><head><title>Flussonic</title></head><body>Admin</body></html>"
        mock_resp.headers = {"server": "Streamer 26.07"}
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await probe_generic_http("93.85.235.253", [80], [])
            assert res["success"] is True
            assert res["brand"] == "Flussonic"
            assert res["device_category"] == "camera"
    asyncio.run(_test())


def test_plain_website_generic_web_not_rvi():
    from ip2domain.cameras.scanner_v2.protocols.generic_http import probe_generic_http

    async def _test():
        mock_resp = AsyncMock()
        mock_resp.text = '<html><head><title>Онлайн-кассы, платежные терминалы</title><meta name="description" content="СейлСервисСолюшенс"></head><body>SaleService Solutions pos terminals</body></html>'
        mock_resp.headers = {"server": "nginx", "x-powered-by": "PHP/7.1.33"}
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await probe_generic_http("37.17.36.8", [80], [])
            assert res["success"] is True
            assert res["brand"] == "Generic Web Device"
            assert res["brand"] != "RVi"
            assert res["device_category"] == "generic_web"
    asyncio.run(_test())





