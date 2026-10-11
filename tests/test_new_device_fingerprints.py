"""Unit tests verifying fingerprinting and categorization for newly added devices."""
import pytest
from ip2domain.cameras.scanner_v2.aggregation import merge_camera_results, merge_host_cameras, _is_camera_brand
from ip2domain.cameras.scanner_v2.models import CameraResult, StreamInfo


def test_tplink_router_not_overridden_to_camera():
    """TP-Link router should retain router category and not be forced into camera."""
    # When router probe identifies TP-Link
    res_map = {
        "router": {
            "success": True,
            "brand": "TP-Link",
            "model": "Archer C20",
            "title": "Archer C20",
            "web_port": 80,
            "web_url": "http://93.125.84.243:80/",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("93.125.84.243", [80], res_map)
    assert cam is not None
    assert cam.brand == "TP-Link"
    assert cam.device_category == "router"
    # Streams should be web_panel, not speculative /snapshot.jpg
    assert len(cam.streams) == 1
    assert cam.streams[0].stream_type == "web_panel"


def test_gpon_broadband_router_not_intercom():
    """GPON router (e.g. 86.57.247.3) with SSLPort / IsMaintWan is classified as router."""
    res_map = {
        "router": {
            "success": True,
            "brand": "Broadband / GPON",
            "model": "Broadband / GPON ONT",
            "title": "Broadband Router Web",
            "web_port": 80,
            "web_url": "http://86.57.247.3:80/",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("86.57.247.3", [80], res_map)
    assert cam is not None
    assert cam.device_category == "router"
    assert "Broadband" in cam.brand or "GPON" in cam.brand


def test_powerlogic_schneider_electric():
    """PowerLogic ION7650 digital power meter is classified as IoT."""
    res_map = {
        "generic": {
            "success": True,
            "brand": "Schneider Electric",
            "model": "PowerLogic ION 7650",
            "title": "PowerLogic ION 7650 Power Quality Analyzer",
            "http_port": 88,
            "device_category": "iot",
            "web_url": "http://178.242.174.54:88/",
        }
    }
    cam = merge_camera_results("178.242.174.54", [88], res_map)
    assert cam is not None
    assert cam.brand == "Schneider Electric"
    assert cam.model == "PowerLogic ION 7650"
    assert cam.device_category == "iot"


def test_coolify_platform():
    """Coolify DevOps PaaS self-hosting platform is classified as server."""
    res_map = {
        "generic": {
            "success": True,
            "brand": "Coolify",
            "model": "Coolify Cloud Platform",
            "title": "Coolify Self-Hosting Platform",
            "http_port": 8000,
            "device_category": "server",
            "web_url": "http://45.129.186.84:8000/",
        }
    }
    cam = merge_camera_results("45.129.186.84", [8000], res_map)
    assert cam is not None
    assert cam.brand == "Coolify"
    assert cam.device_category == "server"


def test_robustel_router():
    """Robustel industrial IoT cellular gateway is classified as router."""
    res_map = {
        "router": {
            "success": True,
            "brand": "Robustel",
            "model": "Robustel Gateway / Router",
            "title": "Robustel Router Web",
            "web_port": 443,
            "web_url": "https://178.242.254.104/auth/",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("178.242.254.104", [443], res_map)
    assert cam is not None
    assert cam.brand == "Robustel"
    assert cam.device_category == "router"


def test_inhand_networks_router():
    """InHand Networks InRouter is classified as router."""
    res_map = {
        "router": {
            "success": True,
            "brand": "InHand Networks",
            "model": "InRouter Industrial Router",
            "title": "InHand InRouter Login",
            "web_port": 80,
            "web_url": "http://176.90.232.55/login.jsp",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("176.90.232.55", [80], res_map)
    assert cam is not None
    assert cam.brand == "InHand Networks"
    assert cam.device_category == "router"


def test_teltonika_router():
    """Teltonika RutOS router is classified as router."""
    res_map = {
        "router": {
            "success": True,
            "brand": "Teltonika",
            "model": "RutOS Gateway / Router",
            "title": "Teltonika RutOS Web",
            "web_port": 80,
            "web_url": "http://188.59.200.185/",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("188.59.200.185", [80], res_map)
    assert cam is not None
    assert cam.brand == "Teltonika"
    assert cam.device_category == "router"


def test_qualvision_intercom():
    """Qualvision / Tantos video intercom is classified as intercom."""
    res_map = {
        "generic": {
            "success": True,
            "brand": "Qualvision / Tantos",
            "model": "IP Intercom (Видеодомофон)",
            "title": "Qualvision / Tantos Video Intercom",
            "http_port": 81,
            "device_category": "intercom",
            "web_url": "http://93.125.84.243:81/",
            "snapshot_path": "/preview.html",
            "rtsp_path": "/live/ch0",
        }
    }
    cam = merge_camera_results("93.125.84.243", [81], res_map)
    assert cam is not None
    assert cam.device_category == "intercom"
    assert "Qualvision" in cam.brand or "Tantos" in cam.brand


def test_tr069_cwmp_agent():
    """TR-069 port 7547 is classified as router / management."""
    res_map = {
        "router": {
            "success": True,
            "brand": "TR-069 CWMP",
            "model": "TR-069 CPE Agent",
            "title": "TR-069 CPE Management Service",
            "web_port": 7547,
            "web_url": "http://93.125.84.243:7547/",
            "device_category": "router",
        }
    }
    cam = merge_camera_results("93.125.84.243", [7547], res_map)
    assert cam is not None
    assert cam.brand == "TR-069 CWMP"
    assert cam.device_category == "router"


def test_bluesis_and_miltera_telemetry():
    """Bluesis and Miltera are classified as IoT."""
    for brand_name in ["Bluesis", "Miltera"]:
        res_map = {
            "generic": {
                "success": True,
                "brand": brand_name,
                "model": f"{brand_name} Telematics Web",
                "title": f"{brand_name} Platform",
                "http_port": 80,
                "device_category": "iot",
                "web_url": "http://1.2.3.4/",
            }
        }
        cam = merge_camera_results("1.2.3.4", [80], res_map)
        assert cam is not None
        assert cam.brand == brand_name
        assert cam.device_category == "iot"


def test_generic_website():
    """Standard website (e.g. 178.124.210.248:80) is classified as generic_web."""
    res_map = {
        "generic": {
            "success": True,
            "brand": "Generic Web Device",
            "model": "nginx",
            "title": "Коктейльная карта",
            "http_port": 80,
            "device_category": "generic_web",
            "web_url": "http://178.124.210.248:80/",
        }
    }
    cam = merge_camera_results("178.124.210.248", [80], res_map)
    assert cam is not None
    assert cam.device_category == "generic_web"
    assert cam.web_title == "Коктейльная карта"


def test_multi_port_host_merge_camera_and_router():
    """Host with router on port 80 and camera on port 81+554 is classified intelligently."""
    c_router = CameraResult(
        ip="91.149.135.93", brand="TP-Link", model="TL-WR840N",
        http_port=80, open_ports=[80], device_category="router"
    )
    c_cam = CameraResult(
        ip="91.149.135.93", brand="Hikvision", model="IP Camera Web Client",
        http_port=81, rtsp_port=554, open_ports=[81, 554], device_category="camera",
        streams=[StreamInfo(url="rtsp://91.149.135.93:554/Streaming/Channels/101", stream_type="rtsp")]
    )
    merged = merge_host_cameras([c_router, c_cam])
    assert merged is not None
    assert merged.device_category == "camera"
    assert len(merged.streams) >= 1
    assert sorted(merged.open_ports) == [80, 81, 554]


def test_signature_patterns_for_all_devices():
    """Verify regex and keyword signatures for all target HTML/headers."""
    import re
    from ip2domain.cameras.scanner_v2.protocols.router import ROUTER_BRAND_SIGNATURES

    sig_map = {brand: patterns for brand, patterns in ROUTER_BRAND_SIGNATURES}

    # 1. 86.57.247.3 GPON router
    gpon_html = "var SSLPort = '80'; var SSLHostIp = '86\\x2e57\\x2e247\\x2e3'; var IsMaintWan = '0'; function IsIPv6AddressUshortValid(s){}"
    assert any(re.search(p, gpon_html, re.I) for p in sig_map["Broadband / GPON"])

    # 2. 178.242.254.104 Robustel
    robustel_html = '<form id="login_form" method="post" action="/weblogin"><span class="icon-ui-user cs_auth_username"></span>'
    assert any(re.search(p, robustel_html, re.I) for p in sig_map["Robustel"])

    # 3. 176.90.232.55 InHand
    inhand_html = '<title>Router -> Login</title> creatAjaxReq("check_auth.jsp?_ajax=1&_username=")'
    assert any(re.search(p, inhand_html, re.I) for p in sig_map["InHand Networks"])

    # 4. 188.59.200.185 Teltonika
    teltonika_html = '<link rel="stylesheet" href="/brand/tokens.css?v=1" /><link rel="stylesheet" href="/brand/colors.css?v=1" />'
    assert any(re.search(p, teltonika_html, re.I) for p in sig_map["Teltonika"])

    # 5. 93.125.84.243:7547 TR-069
    tr069_header = "Server: tr069 http server"
    assert any(re.search(p, tr069_header, re.I) for p in sig_map["TR-069 CWMP"])

    # 6. 93.125.84.243:80 TP-Link Archer C20
    tplink_c20 = 'var modelName="Archer C20"; <link rel="stylesheet" href="../css/jquery.tpInput.css"/>'
    assert any(re.search(p, tplink_c20, re.I) for p in sig_map["TP-Link"])

    # 7. 91.149.135.93:80 TP-Link TL-WR840N
    tplink_wr840n = 'var modelName="TL-WR840N"; <label id="copyright">Copyright © 2016 TP-LINK Technologies Co., Ltd.</label>'
    assert any(re.search(p, tplink_wr840n, re.I) for p in sig_map["TP-Link"])


def test_credentials_preserved_on_multi_port_host():
    """Verify that credentials discovered on one endpoint are not wiped when merging multi-port host."""
    c_router = CameraResult(
        ip="91.149.135.93", brand="TP-Link", model="TL-WR840N",
        http_port=80, open_ports=[80], device_category="router"
    )
    c_cam = CameraResult(
        ip="91.149.135.93", brand="Hikvision", model="IP Camera Web Client",
        http_port=81, rtsp_port=554, open_ports=[81, 554], device_category="camera",
        credentials={"user": "admin", "password": "password123"},
        streams=[StreamInfo(url="rtsp://admin:password123@91.149.135.93:554/Streaming/Channels/101", stream_type="rtsp")]
    )
    merged = merge_host_cameras([c_router, c_cam])
    assert merged is not None
    assert merged.credentials == {"user": "admin", "password": "password123"}
    # Endpoints also have credentials
    cam_eps = [e for e in merged.endpoints if e.get("credentials")]
    assert len(cam_eps) >= 1
    assert cam_eps[0]["credentials"] == {"user": "admin", "password": "password123"}


def test_storage_preserves_credentials_on_update(tmp_path):
    """Verify save_v2_result does not erase existing credentials when receiving empty credentials update."""
    from ip2domain.core.storage import StorageManager
    db_file = tmp_path / "test_creds.db"
    mgr = StorageManager(db_path=str(db_file))
    
    # 1. First save with discovered credentials
    mgr.save_v2_result({
        "ip": "192.168.1.50",
        "brand": "Hikvision",
        "device_category": "camera",
        "credentials": {"user": "admin", "password": "12345admin"},
        "streams": [{"url": "rtsp://192.168.1.50:554/ch1", "type": "rtsp"}],
    })
    
    res1 = mgr.get_v2_result("192.168.1.50")
    assert res1 is not None
    assert res1.get("credentials") == {"user": "admin", "password": "12345admin"}

    # 2. Second update without credentials (e.g. from background capture or stream prune)
    mgr.save_v2_result({
        "ip": "192.168.1.50",
        "brand": "Hikvision",
        "device_category": "camera",
        "credentials": {},
        "streams": [{"url": "rtsp://192.168.1.50:554/ch1", "type": "rtsp", "verified": True}],
    })

    res2 = mgr.get_v2_result("192.168.1.50")
    assert res2 is not None
    assert res2.get("credentials") == {"user": "admin", "password": "12345admin"}
    assert res2.get("streams")[0].get("verified") is True


@pytest.mark.anyio
async def test_web_form_login_generic_html():
    """Verify that probe_web_form_login parses HTML form and submits credentials."""
    from ip2domain.cameras.scanner_v2.protocols.web_login import _extract_html_form_details, probe_web_form_login
    html = '''
    <html>
      <body>
        <form action="/login_check" method="POST">
          <input type="text" name="username" value="" />
          <input type="password" name="password" value="" />
          <button type="submit">Войти</button>
        </form>
      </body>
    </html>
    '''
    details = _extract_html_form_details(html, "http://192.168.1.1/")
    assert details is not None
    assert details["action_url"] == "http://192.168.1.1/login_check"
    assert details["user_field"] == "username"
    assert details["pwd_field"] == "password"


@pytest.mark.anyio
async def test_dual_queue_stage3_execution(tmp_path):
    """Verify _capture_job_streams runs dual queues (HTTP snapshots and streams)."""
    from ip2domain.cameras.scanner_v2.engine import _capture_job_streams
    from ip2domain.cameras.scanner_v2.models import ScanJob, CameraResult, StreamInfo
    from unittest.mock import AsyncMock, patch

    job = ScanJob(job_id="test_dual_queue")
    cam1 = CameraResult(
        ip="1.1.1.1",
        streams=[StreamInfo(url="http://1.1.1.1/snap.jpg", stream_type="http_snapshot")],
    )
    cam2 = CameraResult(
        ip="2.2.2.2",
        streams=[StreamInfo(url="rtsp://2.2.2.2:554/live", stream_type="rtsp")],
    )
    job.results = [cam1, cam2]

    # Mock verify_single_stream to succeed
    async def mock_verify(stream, capture_dir, creds=None):
        stream.verified = True
        stream.screenshot_path = str(capture_dir / "test.jpg")
        return True

    with patch("ip2domain.cameras.scanner_v2.stage3_stream.verify_single_stream", side_effect=mock_verify):
        await _capture_job_streams(job, tmp_path, storage=None)

    assert cam1.streams[0].verified is True
    assert cam2.streams[0].verified is True
    assert job.stage3_status == "done"



