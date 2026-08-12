from ip2domain.modules.camera_scanner import CameraScanner


def test_parse_camera_fingerprints():
    xml = '''<nmaprun><host><address addr="203.0.113.8"/><hostnames><hostname name="cam01.example.net"/></hostnames><ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Hikvision web server"/><script id="http-title" output="Network Camera"/></port>
    <port protocol="tcp" portid="554"><state state="open"/><service name="rtsp" product="Hikvision RTSP"/><script id="rtsp-methods" output="OPTIONS, DESCRIBE"/></port>
    </ports></host></nmaprun>'''
    devices = CameraScanner._parse_nmap(xml)
    assert len(devices) == 1
    assert devices[0]["target"] == "203.0.113.8"
    assert devices[0]["confidence"] == "очень высокая"
    assert {item["criterion"] for item in devices[0]["findings"]} >= {
        "Reverse DNS / PTR", "HTTP / TLS / баннер сервиса", "RTSP"
    }


def test_ignores_unrelated_http_service():
    xml = '''<nmaprun><host><address addr="203.0.113.9"/><ports><port protocol="tcp" portid="80">
    <state state="open"/><service name="http" product="nginx"/></port></ports></host></nmaprun>'''
    assert CameraScanner._parse_nmap(xml) == []


def test_goahead_alone_is_not_enough_to_call_device_a_camera():
    xml = '''<nmaprun><host><address addr="151.237.169.97"/><hostnames>
    <hostname name="151-237-169-97.rdtc.ru"/></hostnames><ports>
    <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="GoAhead WebServer"/></port>
    </ports></host></nmaprun>'''
    assert CameraScanner._parse_nmap(xml) == []


def test_dvr_html_title_is_strong_camera_evidence():
    xml = '''<nmaprun><host><address addr="151.237.169.97"/><ports>
    <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="GoAhead-Webs"/>
    <script id="http-title" output="DVR Remote Management System"/>
    </port></ports></host></nmaprun>'''
    devices = CameraScanner._parse_nmap(xml)
    assert len(devices) == 1
    assert devices[0]["confidence"] == "высокая"
    assert "DVR Remote Management System" in devices[0]["findings"][0]["value"]


def test_camera_discovery_uses_small_batches_and_fast_scripts():
    assert CameraScanner.NMAP_BATCH_SIZE == 32
    assert CameraScanner.NMAP_BATCH_CONCURRENCY == 4
    source = __import__("inspect").getsource(CameraScanner._nmap_batch)
    assert "--script-timeout" in source
    assert "--stats-every" in source
    assert "http-enum" not in source
    assert "http-auth-finder" not in source


def test_http_redirect_body_identifies_goahead_dvr_as_camera():
    findings = CameraScanner._http_findings(
        "151.237.169.97", 80, "http://151.237.169.97:80/home.asp",
        "Server: GoAhead-Webs",
        '<title>DVR Remote Management System</title><script src="/js/web_preview.js"></script>'
        '<a href="ActiveXSetup.zip">plugin</a>',
    )
    device = {"findings": findings}
    CameraScanner._update_confidence(device)

    assert device["score"] == 50
    assert device["confidence"] == "высокая"
    assert any(item["criterion"] == "HTTP HTML/JS fingerprint" for item in findings)
    assert any("DVR Remote Management System" in item["value"] for item in findings)
