import os
import asyncio
import pytest
import shutil
import subprocess
from pathlib import Path

from ip2domain.cli import configure_web_api_token
from ip2domain.web.app import serve_index, serve_login, get_providers


_STATIC_DIR = Path(__file__).resolve().parents[1] / "ip2domain" / "web" / "static"


def test_browser_javascript_has_valid_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    for script in _STATIC_DIR.glob("*.js"):
        subprocess.run([node, "--check", str(script)], check=True, capture_output=True, text=True)


def test_rtsp_credentials_are_kept_in_temporary_server_session():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.72", "services": [{"port": 554, "service": "rtsp", "scripts": []}]
    }])
    response = web_app.create_scanned_camera_connection(web_app.IPCameraConnectionRequest(
        target="203.0.113.72", port=554, username="viewer", password="secret-value",
        rtsp_path="/Streaming/Channels/1"))
    connection = web_app.IP_CAMERA_CONNECTIONS[response["connection_id"]]
    assert connection["password"] == "secret-value"
    assert connection["rtsp_path"] == "/Streaming/Channels/1"
    assert "password" not in response and "username" not in response
    web_app.close_scanned_camera_connection(response["connection_id"])
    assert response["connection_id"] not in web_app.IP_CAMERA_CONNECTIONS


def test_rtsp_connection_rejects_malformed_stream_path():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.73", "services": [{"port": 554, "service": "rtsp", "scripts": []}]
    }])
    with pytest.raises(web_app.HTTPException) as error:
        web_app.create_scanned_camera_connection(web_app.IPCameraConnectionRequest(
            target="203.0.113.73", port=554, rtsp_path="not/absolute"))
    assert error.value.status_code == 400


def test_rtsp_connection_accepts_automatic_path_selection():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.74", "services": [{"port": 554, "service": "rtsp", "scripts": []}]
    }])
    response = web_app.create_scanned_camera_connection(web_app.IPCameraConnectionRequest(
        target="203.0.113.74", port=554, rtsp_path="auto"))
    assert web_app.IP_CAMERA_CONNECTIONS[response["connection_id"]]["rtsp_path"] == "auto"


def test_rtsp_connection_normalizes_full_url_to_path():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.80", "services": [{"port": 554, "service": "rtsp", "scripts": []}]
    }])
    response = web_app.create_scanned_camera_connection(web_app.IPCameraConnectionRequest(
        target="203.0.113.80", port=554, username="admin", password="admin",
        rtsp_path="rtsp://203.0.113.80/CAM_ID.password.mp2"))
    connection = web_app.IP_CAMERA_CONNECTIONS[response["connection_id"]]
    assert connection["rtsp_path"] == "/CAM_ID.password.mp2"


def test_rtsp_connection_rejects_url_for_another_camera():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.81", "services": [{"port": 554, "service": "rtsp", "scripts": []}]
    }])
    with pytest.raises(web_app.HTTPException) as error:
        web_app.create_scanned_camera_connection(web_app.IPCameraConnectionRequest(
            target="203.0.113.81", port=554, rtsp_path="rtsp://203.0.113.82/live.sdp"))
    assert error.value.status_code == 400


def test_rtsp_preview_uses_rtsp_demuxer_timeout_option():
    import inspect
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    source = inspect.getsource(web_app.get_scanned_camera_snapshot)
    assert '"-rtsp_transport", "tcp", "-timeout"' in source
    assert '"-rtsp_transport", "tcp", "-rw_timeout"' not in source


def test_rtsp_video_stream_is_resource_limited_mjpeg():
    import inspect
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    source = inspect.getsource(web_app.stream_scanned_camera)
    assert "IP_CAMERA_STREAM_SEMAPHORE.acquire" in source
    assert '"-f", "mpjpeg"' in source
    assert '"-an"' in source
    assert "StreamingResponse" in source


def test_camera_csv_export_contains_ip_protocols_and_ports():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    web_app.storage.save_camera_devices([{
        "target": "203.0.113.80", "hostname": "cam.example", "score": 95,
        "confidence": "очень высокая", "services": [
            {"port": 554, "service": "rtsp", "scripts": []},
            {"port": 80, "service": "http", "scripts": []},
        ],
    }])
    response = web_app.export_camera_results_csv()
    body = response.body.decode("utf-8")
    assert body.startswith("\ufeffip_address,hostname,score")
    assert "203.0.113.80,cam.example,95" in body
    assert '"HTTP,RTSP"' in body
    assert '"80,554"' in body
    assert "attachment;" in response.headers["content-disposition"]


def test_camera_scan_accepts_ipv4_slash_15_with_default_limit():
    import importlib
    from fastapi import BackgroundTasks
    web_app = importlib.import_module("ip2domain.web.app")
    request = web_app.CameraScanRequest(targets="46.180.0.0/15", ports=[554])
    result = asyncio.run(web_app.start_camera_scan(request, BackgroundTasks()))
    assert result["total_targets"] == 131070


def test_camera_scan_range_limit_error_reports_total_context(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks, HTTPException
    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setenv("IP2DOMAIN_CAMERA_MAX_TARGETS", "5")
    request = web_app.CameraScanRequest(targets="8.8.8.8 9.9.9.0/29", ports=[554])
    with pytest.raises(HTTPException) as error:
        asyncio.run(web_app.start_camera_scan(request, BackgroundTasks()))
    assert "уже добавлено 1" in error.value.detail
    assert "общий лимит 5" in error.value.detail


def test_camera_job_initializes_resource_aware_stage(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")

    async def fake_scan(self, targets, ports, progress_callback, device_callback,
                        cancel_event, concurrency):
        progress_callback(50, "Проверено: 1/1 IP")
        return {"target_count": 1, "devices": [], "camera_count": 0}

    monkeypatch.setattr(web_app.CameraScanner, "scan", fake_scan)
    job_id = "camera-stage-test"
    web_app.CAMERA_JOBS.create(job_id, {"job_id": job_id, "status": "queued"})
    asyncio.run(web_app._run_camera_job(
        job_id, web_app.CameraScanRequest(targets="8.8.8.8", ports=[554]), ["8.8.8.8"]))
    job = web_app.CAMERA_JOBS.get(job_id)
    assert job["status"] == "completed"
    assert job["results"]["target_count"] == 1


def test_serve_index_html():
    response = serve_index()
    assert "ip2domain" in response
    assert "Network Intelligence" in response
    assert 'id="results-view"' in response
    assert 'id="history-view"' in response
    assert 'id="settings-view"' in response
    assert 'id="password-form"' in response
    assert 'class="node-details-drawer"' in response
    assert 'id="sidebar-collapse-button"' in response
    assert 'function toggleSidebarCompact()' in response
    assert 'id="graph-fullscreen-button"' in response
    assert 'async function toggleGraphFullscreen()' in response
    assert 'IP из базы' not in response
    assert 'id="rescan-graph-btn"' in response


def test_graph_rescan_excludes_subdomains_from_targets():
    scan_js = (_STATIC_DIR / "scan.js").read_text(encoding="utf-8")
    rescan_block = scan_js.split("async function rescanCurrentGraph()", 1)[1].split(
        "function _waitForRescanJob", 1
    )[0]

    assert "node.group === 'ip'" in rescan_block
    assert "node.group === 'apex_domain'" in rescan_block
    assert "node.group === 'subdomain'" in rescan_block
    assert "fetch('/api/scan'" in rescan_block


def test_graph_hide_uses_type_aware_cascade():
    graph_js = (_STATIC_DIR / "graph.js").read_text(encoding="utf-8")
    cascade = graph_js.split("function _getCascadeHiddenNodeIds", 1)[1].split(
        "async function hideSelectedNode", 1
    )[0]

    assert "selected.group === 'subdomain'" in cascade
    assert "selected.group === 'apex_domain'" in cascade
    assert "selected.group === 'ip'" in cascade
    assert "node.details.parent === apex" in cascade
    assert ".includes(ip)" in cascade
    assert "hasOutsideDomain" in cascade
    assert "if (!hasOutsideDomain)" in cascade
    assert "getConnectedEdges" not in cascade


def test_nmap_progress_distinguishes_discovery_and_port_scan_phases():
    app_py = (Path(__file__).resolve().parents[1] / "ip2domain" / "web" / "app.py").read_text(encoding="utf-8")
    graph_js = (_STATIC_DIR / "graph.js").read_text(encoding="utf-8")

    assert "Этап 1/2 · Поиск доменов и связей" in app_py
    assert "Этап 2/2 · Nmap" in app_py
    assert "nmapStatus === 'completed'" in graph_js
    assert "Результат Nmap отсутствует" in graph_js
    assert "{nmap_stage_prefix} ({req.nmap_profile}) работает" in app_py
    assert "65 535 TCP-портов" in app_py
    assert "прошло {elapsed} сек." in app_py
    assert "проверено ≈" in (Path(__file__).resolve().parents[1] / "ip2domain" / "modules" / "nmap_scanner.py").read_text(encoding="utf-8")


def test_remote_desktop_view_and_authenticated_capture_api_exist():
    root = Path(__file__).resolve().parents[1]
    html = (root / "ip2domain" / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    app_py = (root / "ip2domain" / "web" / "app.py").read_text(encoding="utf-8")

    assert 'data-view="remote-desktop-view"' in html
    assert 'data-view="cameras-view"' in html
    assert 'id="camera-form"' in html
    assert 'clearCameraResults()' in html
    assert '/api/cameras/scan' in app_py
    assert '/api/cameras/results' in app_py
    assert '/api/cameras/results/export.csv' in app_py
    assert '/api/cameras/connect/snapshot.jpg' in app_py
    assert '/api/cameras/connect/session' in app_py
    assert '/api/cameras/connect/stream.mjpeg' in app_py
    assert '/api/cameras/centra' in app_py
    assert '/api/cameras/centra/discover' in app_py
    assert '/api/cameras/centra/coordinates' in app_py
    assert '/api/cameras/centra/geocode' in app_py
    assert 'дом {current_building:,} из {req.end_id:,}' in app_py
    assert '"flus5.mycentra.ru", "flus6.mycentra.ru"' in app_py
    assert 'automatic_hosts.get(camera_type' in app_py
    assert 'id="camera-centra-panel"' in html
    assert 'id="centra-camera-type"' in html
    assert 'id="centra-custom-type"' in html
    assert 'id="centra-base-url"' in html
    assert 'pattern="https://[A-Za-z0-9-]+\\.mycentra\\.ru"' in html
    assert 'id="centra-pin-color"' in html
    assert 'value="red" selected' in html
    assert '<option value="H">H · Камеры на домах</option>' in html
    assert '<option value="P">P · Камеры на домах</option>' in html
    cameras_js = (_STATIC_DIR / "cameras.js").read_text(encoding="utf-8")
    assert "startCameraVulnScan" in cameras_js
    assert "setCameraConnectionFilter" in cameras_js
    assert "connectToScannedCamera" in cameras_js
    assert "authorizeIPCamera" in cameras_js
    assert "setIPCameraViewMode" in cameras_js
    assert 'name="username" autocomplete="username" value="admin"' in cameras_js
    assert 'name="password" type="password" autocomplete="current-password" value="admin"' in cameras_js
    assert "tech_stack:techStack" in cameras_js
    assert "open_ports:openPorts" in cameras_js
    assert "loadCentraCameras" in cameras_js
    assert "startCentraDiscovery" in cameras_js
    assert "centraCameraNumber" in cameras_js
    assert "centraEntrance" in cameras_js
    assert "iconContent: centraEntrance(camera)" in cameras_js
    assert "camera_type: selectedCentraCameraType()" in cameras_js
    assert "`islands#${color}StretchyIcon`" in cameras_js
    assert "centraClusterGradient" in cameras_js
    assert "centraClusterLayout" in cameras_js
    assert "conic-gradient" in cameras_js
    assert "setCentraListFilter" in cameras_js
    assert "centra-address-group" in cameras_js
    assert "rememberCentraAddressGroup" in cameras_js
    assert "centraSidebarAddress" in cameras_js
    assert 'id="centra-list-filters"' in html
    assert 'class="help-tooltip"' in html
    assert 'data-tooltip=' in html
    assert 'id="centra-skip-existing"' in html
    assert "skip_existing:" in cameras_js
    assert 'id="centra-cancel-button"' in html
    assert 'id="camera-screens-tab"' in html
    assert 'id="centra-screens-grid"' in html
    assert 'id="centra-screen-search"' in html
    assert "scheduleCentraScreensSearch" in cameras_js
    assert "analyzeCentraScreenPeople" in cameras_js
    assert "filterCentraScreensByPeople" in cameras_js
    assert "people_count" in app_py
    assert "assign_identities" in app_py
    assert "/api/cameras/centra/people-identities/reset" in app_py
    assert "/api/cameras/centra/people/results" in app_py
    assert "showSavedCentraPeople" in cameras_js
    assert "updateCentraScreensModeButtons" in cameras_js
    assert 'id="centra-screens-all-button"' in html
    assert 'data-people-filter="1+"' in html
    assert "range === '1+' ? count < 1" in cameras_js
    assert 'id="centra-people-reset"' not in html
    assert '>Найти на всех</button>' in html
    assert "/api/cameras/centra/people-identities/search" in app_py
    assert "personSearch" in cameras_js
    assert "save_centra_reid_states" in app_py
    assert "assign_identities_stateless" in app_py
    assert "_ensure_centra_reid_restored" not in app_py
    assert "/api/cameras/centra/people/active" in app_py
    assert "restoreCentraPeopleAnalysis" in cameras_js
    assert "IP2DOMAIN_CENTRA_PEOPLE_BATCH_PAUSE" in app_py
    assert "all_cameras" in app_py
    assert "cancelCentraPeopleAnalysis" in cameras_js
    assert "matches_from" in app_py
    assert "matchesCursor" in cameras_js
    assert "failure_details" in app_py
    assert "последняя ошибка" in cameras_js
    assert "screenshot_stale" in app_py
    assert "IP2DOMAIN_CENTRA_PEOPLE_PREFETCH" in app_py
    assert "CENTRA_PERSON_FFMPEG_SEMAPHORE" in app_py
    assert '/api/cameras/centra/people' in app_py
    assert "repeat(5,minmax(0,1fr))" in (root / "ip2domain" / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert '/api/cameras/centra/screens' in app_py
    assert "cancelCentraDiscovery" in cameras_js
    assert "loadMoreCentraScreens" in cameras_js
    assert "openCentraScreenCamera" in cameras_js
    assert "openCentraCameraPlayer" in cameras_js
    assert "centraWebrtcEmbedUrl" in cameras_js
    assert "url.searchParams.set('proto', 'webrtc')" in cameras_js
    assert "url.searchParams.set('muted', 'false')" in cameras_js
    assert 'allow="autoplay; fullscreen; encrypted-media"' in cameras_js
    assert "setCentraPlayerMode" in cameras_js
    assert "['I', 'A', 'H'].includes(type)" in cameras_js
    assert "CENTRA_CAPTURE_REFRESH_TASKS" in app_py
    assert 'IP2DOMAIN_CENTRA_SCREEN_TTL", "300"' in app_py
    assert "screenshot_stale" in app_py
    assert "data-refresh=" in cameras_js
    assert 'f"https://{host}/{camera_id}/index.m3u8"' in app_py
    assert 'f"https://{host}/{camera_id}/preview.jpg"' in app_py
    assert "IP2DOMAIN_CENTRA_PREVIEW_CONCURRENCY" in app_py
    assert "IP2DOMAIN_CENTRA_FFMPEG_CONCURRENCY" in app_py
    assert 'image.startswith(b"\\xff\\xd8")' in app_py
    assert "IntersectionObserver" in cameras_js
    assert "_cleanup_centra_captures" in app_py
    assert "serverInput.setCustomValidity" in cameras_js
    assert "Сервер должен быть полным HTTPS URL без пути" in app_py
    assert '/cancel")' in app_py
    assert '@app.get("/api/cameras/centra/discover/active")' in app_py
    assert "centra-job-list" in cameras_js
    assert "formatCentraEta" in cameras_js
    assert "eta_seconds" in app_py
    assert "for attempt in range(2)" in app_py
    assert '"status": "already_running"' in app_py
    assert "await asyncio.sleep(0.35)" in app_py
    assert '"skip_existing": req.skip_existing' in app_py
    assert "if available or conclusive:" in app_py
    assert "camera_hosts.insert(0, saved_host)" in app_py
    assert "groupByCoordinates: false" in cameras_js
    assert "gridSize: 48" in cameras_js
    assert "handleCentraClusterClick(objects)" in cameras_js
    assert "centraMap.getZoom() >= 12" in cameras_js
    assert "openCentraClusterList" in cameras_js
    assert "function openCentraClusterCamera(index) {\n    openCentraCamera(index);" in cameras_js
    assert "type: 'Rectangle', coordinates: [[0, 0], [48, 48]]" in cameras_js
    assert "clusterer.events.add('click'" in cameras_js
    assert "Городская камера" in cameras_js
    assert "Камера на доме" in cameras_js
    assert "updateCentraTypeFields" in cameras_js
    assert "updateCentraColorOptions" in cameras_js
    assert "selectedCentraCameraType" in cameras_js
    assert "if (fixedColor) select.value = fixedColor" in cameras_js
    assert "option.value === fixedColor" in cameras_js
    assert "updateCentraTypeFields();" in cameras_js
    assert "custom-type-active" in cameras_js
    assert 'type_pin_colors' in app_py
    assert "used_pin_colors" in app_py
    assert "missingByAddress" in cameras_js
    assert "'/api/cameras/centra/geocode'" in cameras_js
    assert 'id="remote-desktop-form"' in html
    assert '/api/remote-desktop/capture/{capture_id}' in app_py
    assert '/api/remote-desktop/results' in app_py


def test_scan_progress_is_restored_and_duplicate_target_is_reused():
    scan_js = (_STATIC_DIR / "scan.js").read_text(encoding="utf-8")
    app_py = (Path(__file__).resolve().parents[1] / "ip2domain" / "web" / "app.py").read_text(encoding="utf-8")

    assert "async function restoreActiveScan()" in scan_js
    assert "fetch('/api/scan/active')" in scan_js
    assert "restoreActiveScan();" in scan_js
    assert 'status": "already_running"' in app_py
    assert '@app.get("/api/scan/active")' in app_py


def test_nmap_only_mode_skips_domain_discovery(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")

    class FakeJobs:
        def __init__(self):
            self.state = {"nmap-only": {"job_id": "nmap-only"}}

        def update(self, job_id, **kwargs):
            self.state[job_id].update(kwargs)

    class FakeNmap:
        def __init__(self, **kwargs):
            pass

        def is_available(self):
            return True

        async def scan_ips_concurrently(self, ips, **kwargs):
            return {ip: {"open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
                         "error": "", "tech_stack": ["HTTPS"]} for ip in ips}

    saved = {}
    monkeypatch.setattr(web_app, "JOBS", FakeJobs())
    monkeypatch.setattr(web_app, "NmapScanner", FakeNmap)
    monkeypatch.setattr(web_app.storage, "save_scan", lambda **kwargs: saved.update(kwargs))
    monkeypatch.setattr(web_app, "ProviderManager", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("ProviderManager must not run in Nmap-only mode")
    ))

    req = web_app.ScanRequest(target="8.8.8.8", scan_mode="nmap", nmap_profile="fast")
    asyncio.run(web_app._run_scan_job("nmap-only", req))

    assert saved["nmap"] is True
    assert saved["results"][0]["domains"] == []
    assert saved["results"][0]["open_ports"][0]["port"] == 443


def test_serve_login_html():
    response = serve_login()
    assert "Вход в панель" in response
    assert 'autocomplete="current-password"' in response


def test_completed_scan_appends_to_current_canvas():
    scan_js = (_STATIC_DIR / "scan.js").read_text(encoding="utf-8")
    completed_block = scan_js.split("if (job.status === 'completed')", 1)[1].split(
        "} else if (job.status === 'error')", 1
    )[0]

    assert "appendScanToCurrentGraph(jobId)" in completed_block
    assert "loadScanGraph(jobId)" not in completed_block
    assert "loadGlobalGraph()" not in completed_block

    assert "function _mergeScanResults" in scan_js
    assert "function _mergeGraphData" in scan_js
    assert "network.getPositions()" in scan_js


def test_get_providers_api():
    data = get_providers()
    assert "ptr" in data
    assert "hackertarget" in data
    assert "urlscan" in data
    assert "virustotal" in data
    assert "shodan" in data
    assert "censys" in data


def test_centra_address_disambiguates_tolyatti_street_in_novokuznetsk(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")

    monkeypatch.setenv("IP2DOMAIN_CENTRA_CITY", "Новокузнецк")
    monkeypatch.setenv("IP2DOMAIN_CENTRA_REGION", "Кемеровская область")
    assert web_app._centra_address("Домофон Тольятти 2 (Новокузнецк)") == \
        "Россия, Кемеровская область, Новокузнецк, ул. Тольятти, 2"
    assert web_app._centra_address("Домофон Тольятти 16") == \
        "Россия, Кемеровская область, Новокузнецк, ул. Тольятти, 16"
    assert web_app._centra_address("Домофон Герцена 3 (Новокузнецк)") == \
        "Россия, Кемеровская область, Новокузнецк, ул. Герцена, 3"
    assert web_app._centra_address("Домофон Нестерова 26а") == \
        "Россия, Кемеровская область, Осинники, ул. Нестерова, 26а"
    assert web_app._centra_address("Домофон 50 лет Октября 31") == \
        "Россия, Кемеровская область, Осинники, ул. 50 лет Октября, 31"
    assert web_app._centra_address("Домофон Таштагол, 8 марта, 1") == \
        "Россия, Кемеровская область, Таштагол, ул. 8 Марта, 1"
    assert web_app._centra_address("Домофон Шерегеш, Гагарина, 8") == \
        "Россия, Кемеровская область, Шерегеш, ул. Гагарина, 8"
    assert web_app._centra_address("Домофон Таштагол, Ноградская, 8") == \
        "Россия, Кемеровская область, Таштагол, ул. Ноградская, 8"
    assert web_app._dadata_address(
        "Россия, Кемеровская область, Новокузнецк, ул. Казарновского, 5"
    ) == "Россия, Кемеровская область, Новокузнецк, Казарновского, 5"
    assert web_app._centra_locality(
        "Россия, Кемеровская область, Осинники, ул. Революции, 35"
    ) == "Осинники"
    assert web_app._centra_locality(
        "Россия, Кемеровская область, Шерегеш, ул. Дзержинского, 6"
    ) == "Шерегеш"
    assert web_app._dadata_queries(
        "Россия, Кемеровская область, Новокузнецк, ул. Рихарда Зорге, 2"
    ) == [
        "Россия, Кемеровская область, Новокузнецк, Рихарда Зорге, 2",
        "Россия, Кемеровская область, Новокузнецк, Зорге, 2",
    ]
    assert web_app._dadata_queries(
        "Россия, Кемеровская область, Новокузнецк, ул. 13-й микрорайон, 12"
    ) == [
        "Россия, Кемеровская область, Новокузнецк, 13-й микрорайон, 12",
        "Россия, Кемеровская область, Новокузнецк, Микрорайон 13, 12",
    ]


def test_centra_api_removes_legacy_webrtc_query(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [{
        "id": "I-296-2", "title": "Домофон Тестовая 1",
        "embed_url": "https://flus4.mycentra.ru/I-296-2/embed.html?proto=webrtc",
    }])
    monkeypatch.setattr(web_app.storage, "get_centra_coordinates", lambda addresses: {})

    camera = web_app.get_centra_cameras()["cameras"][0]
    assert camera["embed_url"] == "https://flus4.mycentra.ru/I-296-2/embed.html"


def test_centra_api_exposes_color_of_temporarily_unavailable_type(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [{
        "id": "T-10-1", "camera_type": "T", "pin_color": "violet", "available": False,
    }])
    monkeypatch.setattr(web_app.storage, "get_centra_coordinates", lambda addresses: {})

    result = web_app.get_centra_cameras()

    assert result["cameras"] == []
    assert result["type_pin_colors"]["T"] == "violet"
    assert result["used_pin_colors"]["violet"] == "T"


def test_centra_pin_colors_are_fixed_per_type(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks
    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [{
        "id": "T-10-1", "camera_type": "T", "pin_color": "violet"
    }])

    background_tasks = BackgroundTasks()
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="T", pin_color="orange", start_id=1, end_id=1
    ), background_tasks))

    assert result["status"] == "queued"
    assert background_tasks.tasks[0].args[1].pin_color == "violet"


def test_custom_centra_color_is_not_reserved_without_saved_camera(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks
    web_app = importlib.import_module("ip2domain.web.app")

    class FakeJobs:
        def create(self, job_id, state):
            return state

    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [])
    monkeypatch.setattr(web_app, "CENTRA_JOBS", FakeJobs())

    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="H", base_url="https://flus5.mycentra.ru", pin_color="green",
        start_id=1, end_id=1, entrance_start=1, entrance_end=1
    ), BackgroundTasks()))
    assert result["status"] == "queued"

    # Custom types may also use automatic host discovery without base_url.
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="Z", pin_color="orange", start_id=1, end_id=1,
        entrance_start=1, entrance_end=1
    ), BackgroundTasks()))
    assert result["status"] == "queued"

    # A different custom type may use another free color.
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="K", base_url="https://flus5.mycentra.ru", pin_color="pink",
        start_id=1, end_id=1, entrance_start=1, entrance_end=1
    ), BackgroundTasks()))
    assert result["status"] == "queued"


def test_centra_custom_type_lists_and_ranges_exclude_builtins():
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    assert web_app._centra_discovery_types("H,P") == ["H", "P"]
    expanded = web_app._centra_discovery_types("A-Z")
    assert len(expanded) == 24
    assert "A" in expanded and "Z" in expanded
    assert "I" not in expanded and "G" not in expanded


def test_centra_type_range_skips_types_with_saved_cameras(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks
    web_app = importlib.import_module("ip2domain.web.app")

    class FakeJobs:
        def create(self, job_id, state):
            return state

    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [
        {"id": "H-10-1", "camera_type": "H", "pin_color": "green"},
        {"id": "P-20-1", "camera_type": "P", "pin_color": "green"},
    ])
    monkeypatch.setattr(web_app, "CENTRA_JOBS", FakeJobs())
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="A-Z", pin_color="violet", start_id=1, end_id=1,
        entrance_start=1, entrance_end=1, skip_existing=True,
    ), BackgroundTasks()))
    assert result["excluded_types"] == ["H", "P"]
    assert "H" not in result["types"] and "P" not in result["types"]
    assert len(result["types"]) == 22
    assert len(result["job_ids"]) == 22

def test_centra_discovery_accepts_entrance_range_and_rejects_reverse_range(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks, HTTPException
    web_app = importlib.import_module("ip2domain.web.app")

    class FakeJobs:
        def create(self, job_id, state):
            assert state["total"] == 6  # 2 houses × entrances 3, 4, 5
            return state

    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [])
    monkeypatch.setattr(web_app, "CENTRA_JOBS", FakeJobs())
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="I", pin_color="red", start_id=10, end_id=11,
        entrance_start=3, entrance_end=5
    ), BackgroundTasks()))
    assert result["total"] == 6

    with pytest.raises(HTTPException, match="Конечный подъезд"):
        asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
            camera_type="I", pin_color="red", start_id=10, end_id=11,
            entrance_start=5, entrance_end=3
        ), BackgroundTasks()))


def test_centra_discovery_limit_is_configurable(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks, HTTPException
    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [])
    monkeypatch.setenv("IP2DOMAIN_CENTRA_SCAN_LIMIT", "200000")

    with pytest.raises(HTTPException, match="200,000"):
        asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
            camera_type="I", pin_color="red", start_id=1, end_id=40000,
            entrance_start=6, entrance_end=11
        ), BackgroundTasks()))


def test_centra_discovery_skips_existing_camera_ids(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks
    web_app = importlib.import_module("ip2domain.web.app")

    class FakeJobs:
        def create(self, job_id, state):
            return state

    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [
        {"id": "I-10-1"}, {"id": "I-10-2"}, {"id": "G-10-1"}, {"id": "I-99-1"}
    ])
    monkeypatch.setattr(web_app.storage, "get_centra_checked_ids", lambda *args: [])
    monkeypatch.setattr(web_app, "CENTRA_JOBS", FakeJobs())
    result = asyncio.run(web_app.start_centra_discovery(web_app.CentraDiscoveryRequest(
        camera_type="I", pin_color="red", start_id=10, end_id=10,
        entrance_start=1, entrance_end=3, skip_existing=True
    ), BackgroundTasks()))
    assert result["total"] == 1
    assert result["skipped"] == 2


def test_centra_people_all_mode_uses_available_database_cameras(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks

    web_app = importlib.import_module("ip2domain.web.app")
    monkeypatch.setattr("ip2domain.core.person_detector.available", lambda _path: True)
    monkeypatch.setattr(web_app.storage, "get_centra_cameras", lambda: [
        {"id": "I-1-1", "available": True},
        {"id": "G-2-1", "available": False},
        {"id": "H-3-1", "available": True},
    ])

    result = asyncio.run(web_app.start_centra_person_detection(
        web_app.CentraPersonDetectionRequest(all_cameras=True, camera_type="I"), BackgroundTasks()))

    assert result["total"] == 1
    assert result["all_cameras"] is True
    assert result["camera_type"] == "I"
    assert result["batch_size"] == 100
    result["matches"].extend([
        {"camera_id": "I-1-1"},
        {"camera_id": "I-2-1"},
    ])
    delta = web_app.get_centra_person_detection(result["job_id"], matches_from=1)
    assert delta["matches"] == [{"camera_id": "I-2-1"}]
    assert delta["matches_total"] == 2


def test_active_centra_people_job_can_be_restored_after_page_reload():
    import importlib

    web_app = importlib.import_module("ip2domain.web.app")
    web_app.CENTRA_PERSON_JOBS["people-active"] = {
        "job_id": "people-active", "status": "running", "stage": "Проверено 10 из 100",
        "total": 100, "checked": 10, "all_cameras": True, "failed": 1,
    }
    web_app.CENTRA_PERSON_JOBS["people-done"] = {
        "job_id": "people-done", "status": "completed", "total": 5,
    }

    result = web_app.get_active_centra_person_detection()

    assert result["job"]["job_id"] == "people-active"
    assert result["job"]["checked"] == 10


def test_centra_people_refreshes_stale_screenshot_before_detection(monkeypatch, tmp_path):
    import importlib
    import time

    web_app = importlib.import_module("ip2domain.web.app")
    capture = tmp_path / "I-9-1.jpg"
    capture.write_bytes(b"old")
    old_time = time.time() - 3600
    os.utime(capture, (old_time, old_time))

    assert web_app._centra_capture_is_stale(capture, 300) is True
    os.utime(capture, None)
    assert web_app._centra_capture_is_stale(capture, 300) is False
    assert web_app._centra_capture_is_stale(tmp_path / "missing.jpg", 300) is True


def test_centra_people_frame_prefetch_uses_person_ffmpeg_limit(monkeypatch, tmp_path):
    import importlib

    web_app = importlib.import_module("ip2domain.web.app")
    seen_semaphores = []

    async def fake_generate(camera_id, _camera, path, _ffmpeg, semaphore=None):
        seen_semaphores.append(semaphore)
        path.write_bytes(camera_id.encode())

    monkeypatch.setattr(web_app, "CENTRA_CAPTURE_DIR", tmp_path)
    monkeypatch.setattr(web_app.storage, "get_centra_camera", lambda camera_id: {"id": camera_id})
    monkeypatch.setattr(web_app, "_generate_centra_screenshot", fake_generate)

    result = asyncio.run(web_app._prepare_centra_person_frame("I-9-1", 300, "ffmpeg"))

    assert result[3] is None
    assert result[2].read_bytes() == b"I-9-1"
    assert seen_semaphores == [web_app.CENTRA_PERSON_FFMPEG_SEMAPHORE]


def test_external_web_host_generates_api_token(monkeypatch):
    monkeypatch.delenv("IP2DOMAIN_API_TOKEN", raising=False)

    generated = configure_web_api_token("0.0.0.0")

    assert generated
    assert os.environ["IP2DOMAIN_API_TOKEN"] == generated


def test_existing_api_token_is_preserved(monkeypatch):
    monkeypatch.setenv("IP2DOMAIN_API_TOKEN", "configured-token")

    generated = configure_web_api_token("0.0.0.0")

    assert generated is None
    assert os.environ["IP2DOMAIN_API_TOKEN"] == "configured-token"


def test_loopback_host_does_not_generate_api_token(monkeypatch):
    monkeypatch.delenv("IP2DOMAIN_API_TOKEN", raising=False)

    generated = configure_web_api_token("127.0.0.1")

    assert generated is None
    assert "IP2DOMAIN_API_TOKEN" not in os.environ
