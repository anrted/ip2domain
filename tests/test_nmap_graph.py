import pytest

from ip2domain.modules.nmap_scanner import NmapScanner, SCAN_PROFILES
from ip2domain.core.graph_builder import GraphBuilder


def test_nmap_scanner_availability():
    scanner = NmapScanner()
    # Nmap is installed on the system
    assert scanner.is_available() is True


def test_graph_builder_structure():
    sample_results = [
        {
            "ip": "194.33.15.13",
            "domains": ["kg17.ru", "detiraduga.kemobl.ru"],
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
            "verified_live": True,
        }
    ]

    graph = GraphBuilder.build_graph(sample_results)

    assert "nodes" in graph
    assert "edges" in graph
    assert graph["stats"]["ip_count"] == 1
    assert graph["stats"]["apex_count"] == 2 # kg17.ru, kemobl.ru
    assert graph["stats"]["subdomain_count"] == 1 # detiraduga.kemobl.ru

    # Verify IP node structure
    ip_node = next(n for n in graph["nodes"] if n["id"] == "ip:194.33.15.13")
    assert ip_node["group"] == "ip"
    assert ip_node["details"]["open_ports"][0]["port"] == 80


@pytest.mark.parametrize("ports,expected", [
    ("22, 80,443", "22,80,443"),
    ("1-1024", "1-1024"),
    (None, None),
])
def test_nmap_port_validation(ports, expected):
    assert NmapScanner.validate_ports(ports) == expected


@pytest.mark.parametrize("ports", ["0", "65536", "100-1", "22;whoami", "-p80", "1,,2"])
def test_nmap_rejects_unsafe_or_invalid_ports(ports):
    with pytest.raises(ValueError):
        NmapScanner.validate_ports(ports)


def test_nmap_profiles_skip_ping_discovery():
    assert all("-Pn" in arguments for arguments in SCAN_PROFILES.values())


def test_nmap_reports_stats_and_counts_requested_ports():
    full = NmapScanner(profile="full")
    custom = NmapScanner(ports="1-10,8,80,443")

    assert full.port_count() == 65535
    assert custom.port_count() == 12
    assert "--stats-every" in full._build_cmd("203.0.113.10")


def test_nmap_xml_includes_service_version_and_risk():
    xml = """<nmaprun><host><status state="up"/><hostnames><hostname name="host.example"/></hostnames>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"><cpe>cpe:/a:openbsd:openssh:9.6</cpe></service></port></ports>
    </host></nmaprun>"""
    result = NmapScanner()._parse_xml("203.0.113.10", xml)

    assert result["hostname"] == "host.example"
    assert result["open_ports"] == [{
        "port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
        "version": "OpenSSH 9.6", "cpe": "cpe:/a:openbsd:openssh:9.6", "risk": "critical",
        "service_method": "", "service_confidence": 0, "tunnel": "", "http_detected": False,
    }]
    assert result["tech_stack"] == ["OpenSSH 9.6"]


def test_nmap_tech_stack_uses_versions_and_skips_generic_services():
    stack = NmapScanner.extract_tech_stack([
        {"port": 21, "service": "ftp", "version": "vsftpd 3.0.5"},
        {"port": 80, "service": "http", "version": "nginx 1.18.0 Ubuntu"},
        {"port": 443, "service": "http", "version": "nginx 1.18.0 Ubuntu"},
        {"port": 445, "service": "netbios-ssn", "version": "Samba smbd 4.6.2"},
        {"port": 2001, "service": "dc", "version": ""},
    ])

    assert stack == ["nginx 1.18.0 Ubuntu", "Samba smbd 4.6.2", "vsftpd 3.0.5"]


def test_nmap_stack_normalization_prefers_versioned_product():
    assert NmapScanner.normalize_tech_stack(["Nginx", "nginx", "nginx 1.18.0 Ubuntu"]) == [
        "nginx 1.18.0 Ubuntu"
    ]
