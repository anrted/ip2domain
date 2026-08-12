import os
import asyncio
from pathlib import Path

from ip2domain.cli import configure_web_api_token
from ip2domain.web.app import serve_index, serve_login, get_providers


_STATIC_DIR = Path(__file__).resolve().parents[1] / "ip2domain" / "web" / "static"


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
    assert '/api/cameras/centra' in app_py
    assert '/api/cameras/centra/discover' in app_py
    assert 'Дом {current_building:,} из {req.end_id:,}' in app_py
    assert 'id="camera-centra-panel"' in html
    cameras_js = (_STATIC_DIR / "cameras.js").read_text(encoding="utf-8")
    assert "startCameraVulnScan" in cameras_js
    assert "tech_stack:techStack" in cameras_js
    assert "open_ports:openPorts" in cameras_js
    assert "loadCentraCameras" in cameras_js
    assert "startCentraDiscovery" in cameras_js
    assert "centraCameraNumber" in cameras_js
    assert "centraEntrance" in cameras_js
    assert "iconContent: centraEntrance(camera)" in cameras_js
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
