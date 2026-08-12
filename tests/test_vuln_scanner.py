import uuid
import asyncio
from fastapi import BackgroundTasks


def test_vuln_scan_endpoints(monkeypatch):
    import importlib
    web_app = importlib.import_module("ip2domain.web.app")
    unique_target = f"test-{uuid.uuid4().hex[:6]}.local"

    async def allow_target(target):
        return True, target

    async def fake_job(job_id, target, tech_stack=None):
        web_app.VULN_JOBS.update(job_id, status="completed", progress_pct=100,
                                 results={"target": target, "total_findings": 0})

    monkeypatch.setattr(web_app, "validate_network_target", allow_target)
    monkeypatch.setattr(web_app, "_run_vuln_scan_job", fake_job)

    # Exercise handlers directly; external scanners and network are mocked.
    res = asyncio.run(web_app.check_vuln_scan_target(unique_target))
    assert res["status"] == "idle"

    req = web_app.VulnScanRequest(target=unique_target, target_type="domain")
    start_res = asyncio.run(web_app.start_vuln_scan(req, BackgroundTasks()))
    assert start_res["status"] == "queued"
    job_id = start_res["job_id"]

    status_res = web_app.get_vuln_scan_status(job_id)
    assert status_res["job_id"] == job_id


def test_stack_adaptation():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    tech_stack = ["ASP.NET", "Bitrix", "IIS", "Microsoft-IIS", "PHP"]
    adapted = scanner.configure_for_stack(tech_stack)

    assert "ASP.NET" in adapted or "asp.net" in [a.lower() for a in adapted]
    assert "http-iis-short-name-brute" in scanner.nmap_args
    assert "http-vuln-cve2015-1635" in scanner.nmap_args
    assert "-Tuning" in scanner.nikto_args


def test_vulnerability_nmap_targets_known_tcp_and_udp_ports():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    command = scanner._build_nmap_command("203.0.113.10", [
        {"port": 8443, "protocol": "tcp", "service": "https-alt"},
        {"port": 53, "protocol": "udp", "service": "domain"},
    ])

    assert "--top-ports" not in command
    assert "-Pn" in command
    assert "-sU" in command
    assert "--stats-every" in command
    assert command[command.index("-p") + 1] == "T:8443,U:53"


def test_warning_is_counted_as_medium_risk():
    from ip2domain.modules.vuln_scanner import _count_severities

    counts = _count_severities([{"severity": "warning"}, {"severity": "critical"}])
    assert counts["medium"] == 1
    assert counts["critical"] == 1


def test_service_stack_enables_installed_targeted_nse_scripts():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    scanner.configure_for_stack(["OpenSSH 8.9p1", "Samba smbd 4.6.2", "vsftpd 3.0.5", "nginx 1.18.0"])

    for script in ("ssh-auth-methods", "smb-vuln-ms17-010", "ftp-vsftpd-backdoor", "http-security-headers"):
        assert script in scanner.nmap_args
    assert "http-nginx-building-brute" not in scanner.nmap_args
    assert "http-wordpress-vuln" not in scanner.nmap_args


def test_nikto_selects_fingerprinted_nonstandard_web_ports():
    from ip2domain.modules.vuln_scanner import VulnScanner

    ports = [
        {"port": 2003, "protocol": "tcp", "service": "finger", "http_detected": True},
        {"port": 9090, "protocol": "tcp", "service": "zeus-admin", "tunnel": "ssl"},
        {"port": 4330, "protocol": "tcp", "service": "dey-sapi"},
    ]
    assert [p["port"] for p in VulnScanner._select_nikto_ports(ports)] == [2003, 9090]


def test_nikto_findings_are_attributed_to_endpoint_and_safe_headers_are_info():
    from ip2domain.modules.vuln_scanner import VulnScanner

    findings = VulnScanner()._parse_nikto_text(
        "+ Uncommon header 'x-xss-protection' found, with contents: 1; mode=block\n"
        "+ /admin/index.html: admin page detected",
        port_info={"port": 9090, "protocol": "tcp", "service": "https-alt"},
        target="203.0.113.10",
    )

    assert all(item["endpoint"] == "203.0.113.10:9090" for item in findings)
    assert all(item["port"] == "9090/tcp" for item in findings)
    assert findings[0]["severity"] == "info"


def test_cockpit_is_detected_from_cookie_evidence_not_port_alone():
    from ip2domain.modules.vuln_scanner import VulnScanner

    cockpit = [{"endpoint": "203.0.113.10:9090", "details": "Cookie cockpit created without the secure flag", "service": "zeus-admin"}]
    unrelated = [{"endpoint": "203.0.113.10:9090", "details": "Generic web application", "service": "http"}]

    assert VulnScanner._fingerprint_findings(cockpit) == ["Cockpit"]
    assert cockpit[0]["service"] == "Cockpit Web Console"
    assert cockpit[0]["technology"] == "Cockpit"
    assert VulnScanner._fingerprint_findings(unrelated) == []


def test_cve_coverage_is_built_for_each_versioned_cpe_service():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    coverage = scanner._build_service_coverage([
        {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 3.0.5", "cpe": "cpe:/a:vsftpd:vsftpd:3.0.5"},
        {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "version": "Samba smbd 4.6.2", "cpe": "cpe:/a:samba:samba:4.6.2"},
    ])

    assert coverage[0]["targeted_scripts"] == ["ftp-anon", "ftp-syst", "ftp-vsftpd-backdoor"]
    assert "smb-vuln-ms17-010" in coverage[1]["targeted_scripts"]
    assert all("Vulners CVE by CPE" in item["checks"] for item in coverage)


def test_embedded_camera_service_profiles_add_targeted_checks():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    ports = [
        {"port": 23, "protocol": "tcp", "service": "telnet",
         "version": "NASLite-SMB/Sveasoft Alchemy firmware telnetd"},
        {"port": 80, "protocol": "tcp", "service": "http",
         "version": "GoAhead WebServer", "http_detected": True},
        {"port": 102, "protocol": "tcp", "service": "iso-tsap", "version": ""},
        {"port": 101, "protocol": "tcp", "service": "hostname", "version": ""},
        {"port": 6623, "protocol": "tcp", "service": "telnet", "version": ""},
        {"port": 8670, "protocol": "tcp", "service": "tcpwrapped", "version": ""},
    ]
    command = " ".join(scanner._build_nmap_command("203.0.113.10", ports))

    for script in ("telnet-encryption", "telnet-ntlm-info", "s7-info",
                   "http-default-accounts", "http-security-headers", "http-server-header"):
        assert script in command
    coverage = scanner._build_service_coverage(ports)
    assert next(item for item in coverage if item["port"] == 102)["targeted_scripts"] == ["s7-info"]
    assert next(item for item in coverage if item["port"] == 101)["targeted_scripts"] == ["banner"]


def test_goahead_stack_enables_embedded_http_profile():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    assert scanner.configure_for_stack(["GoAhead WebServer"]) == ["GoAhead WebServer"]
    assert "http-default-accounts" in scanner.nmap_args
    assert "http-methods" in scanner.nmap_args


def test_dvr_services_are_profiled_by_fingerprint_on_nonstandard_ports():
    from ip2domain.modules.vuln_scanner import VulnScanner

    scanner = VulnScanner()
    ports = [
        {"port": 2323, "protocol": "tcp", "service": "telnet", "version": "camera telnetd"},
        {"port": 8181, "protocol": "tcp", "service": "http-alt",
         "version": "GoAhead DVR Remote Management System", "http_detected": True},
        {"port": 1102, "protocol": "tcp", "service": "iso-tsap", "version": ""},
        {"port": 9554, "protocol": "tcp", "service": "rtsp", "version": "IP Camera RTSP"},
    ]
    command = " ".join(scanner._build_nmap_command("203.0.113.10", ports))

    assert "-p T:1102,2323,8181,9554" in command
    for script in ("telnet-encryption", "s7-info", "http-default-accounts",
                   "rtsp-methods", "rtsp-url-brute"):
        assert script in command

    scanner.configure_for_stack(["GoAhead DVR Remote Management System"])
    assert "GoAhead DVR Remote Management System" in scanner.adapted_stack
    assert "rtsp-methods" in scanner.nmap_args
