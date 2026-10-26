"""Unit tests for WordPress Hunter module and API endpoints."""
import pytest
from ip2domain.modules.wp_hunter import (
    WPHunter,
    _GENERATOR_REGEX,
    _FEED_GENERATOR_REGEX,
    _CORE_ASSET_VER_REGEX,
    _README_VERSION_REGEX,
    _THEME_REGEX,
    _PLUGIN_REGEX,
)


def test_target_parsing_cidr_and_domains():
    hunter = WPHunter()
    raw = [
        "example.com",
        "https://eshdesign.ru:8443/",
        "192.168.1.0/30",
        "10.0.0.1:8080",
        "# comment",
        "  ",
    ]
    parsed = hunter.parse_targets(raw, ports=[80, 443])

    # Check example.com (both 80 and 443)
    ex_80 = next((t for t in parsed if t["host"] == "example.com" and t["port"] == 80), None)
    ex_443 = next((t for t in parsed if t["host"] == "example.com" and t["port"] == 443), None)
    assert ex_80 is not None
    assert ex_443 is not None

    # Check https://eshdesign.ru:8443
    esh = next((t for t in parsed if t["host"] == "eshdesign.ru" and t["port"] == 8443), None)
    assert esh is not None
    assert esh["scheme"] == "https"

    # Check 192.168.1.0/30 expansion (hosts: .1, .2)
    c_1 = next((t for t in parsed if t["host"] == "192.168.1.1" and t["port"] == 80), None)
    c_2 = next((t for t in parsed if t["host"] == "192.168.1.2" and t["port"] == 80), None)
    assert c_1 is not None
    assert c_2 is not None

    # Check 10.0.0.1:8080
    host_port = next((t for t in parsed if t["host"] == "10.0.0.1" and t["port"] == 8080), None)
    assert host_port is not None


def test_version_regex_extractors():
    # Meta generator
    html_gen = '<meta name="generator" content="WordPress 6.4.3" />'
    m = _GENERATOR_REGEX.search(html_gen)
    assert m is not None
    assert m.group(1) == "6.4.3"

    # Feed generator
    xml_feed = '<generator>https://wordpress.org/?v=6.5.2</generator>'
    m2 = _FEED_GENERATOR_REGEX.search(xml_feed)
    assert m2 is not None
    assert m2.group(1) == "6.5.2"

    # Asset version query
    html_asset = '<script src="/wp-includes/js/wp-embed.min.js?ver=6.3.1"></script>'
    m3 = _CORE_ASSET_VER_REGEX.findall(html_asset)
    assert m3 == ["6.3.1"]

    # Readme
    readme_sample = "<title>WordPress &#8250; ReadMe</title>\n<h1>Version 6.2.2</h1>"
    m4 = _README_VERSION_REGEX.search(readme_sample)
    assert m4 is not None
    assert m4.group(1) == "6.2.2"

    # Theme & Plugins
    html_comps = """
    <link rel="stylesheet" href="/wp-content/themes/woodmart/style.css" />
    <script src="/wp-content/plugins/woocommerce/assets/js/frontend.js"></script>
    <script src="/wp-content/plugins/elementor/assets/js/frontend.js"></script>
    """
    themes = _THEME_REGEX.findall(html_comps)
    assert "woodmart" in themes
    plugins = _PLUGIN_REGEX.findall(html_comps)
    assert "woocommerce" in plugins
    assert "elementor" in plugins


def test_storage_mixin_wp_methods():
    from ip2domain.core.storage import StorageManager
    import tempfile
    import os

    tmp = tempfile.mktemp(suffix=".db")
    try:
        storage = StorageManager(db_path=tmp)
        job_id = "test_wp_1"
        job = storage.create_wp_job(job_id, "eshdesign.ru", [80, 443], 2)
        assert job["id"] == job_id
        assert job["status"] == "running"

        # Batch save
        mock_results = [
            {
                "url": "https://eshdesign.ru",
                "host": "eshdesign.ru",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "is_wordpress": True,
                "version": "6.5.2",
                "version_source": "meta_generator",
                "title": "Esh Design Studio",
                "server": "nginx",
                "theme": "woodmart",
                "plugins": ["elementor", "woocommerce"],
                "security": {"xmlrpc_open": False, "users_exposed": ["admin"]},
                "latency_ms": 12.5,
            },
            {
                "url": "http://other.com",
                "host": "other.com",
                "port": 80,
                "scheme": "http",
                "status_code": 200,
                "is_wordpress": False,
                "latency_ms": 8.0,
            }
        ]
        storage.save_wp_results_batch(job_id, mock_results)
        storage.update_wp_job(job_id, status="completed", completed_targets=2, found_wp=1, finished=True)

        # Query
        res_wp = storage.get_wp_results(job_id=job_id, only_wp=True)
        assert res_wp["total"] == 1
        assert res_wp["items"][0]["host"] == "eshdesign.ru"
        assert res_wp["items"][0]["version"] == "6.5.2"
        assert "elementor" in res_wp["items"][0]["plugins"]
        assert res_wp["items"][0]["security"]["users_exposed"] == ["admin"]

        # Stats
        stats = storage.get_wp_stats()
        assert stats["total_scanned"] == 2
        assert stats["total_wp"] == 1
        assert stats["total_versions"] == 1
        assert "elementor" in stats["top_plugins"]
        assert "woodmart" in stats["top_themes"]

    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def test_api_wp_endpoints():
    from fastapi.testclient import TestClient
    from ip2domain.web.app import app

    client = TestClient(app)
    # Stats
    r_stats = client.get("/api/wp/stats")
    assert r_stats.status_code == 200
    data = r_stats.json()
    assert "total_scanned" in data
    assert "total_wp" in data

    # Results
    r_res = client.get("/api/wp/results")
    assert r_res.status_code == 200
    assert "items" in r_res.json()

    # Import topology
    r_imp = client.post("/api/wp/import_topology")
    assert r_imp.status_code == 200
    assert "targets" in r_imp.json()


def test_wp_cve_checks():
    from ip2domain.modules.wp_hunter import parse_wp_version, check_wp_cves

    # Version parsing
    assert parse_wp_version("6.9.2") == (6, 9, 2)
    assert parse_wp_version("6.8") == (6, 8, 0)
    assert parse_wp_version("7.0.1") == (7, 0, 1)
    assert parse_wp_version("invalid") is None

    # Test 6.9.2: vulnerable to both CVE-2026-63030 and CVE-2026-60137 -> wp2shell!
    res_692 = check_wp_cves("6.9.2", batch_api_status=400, batch_api_open=True)
    cve_ids = [c["cve"] for c in res_692["cves"]]
    assert "CVE-2026-63030" in cve_ids
    assert "CVE-2026-60137" in cve_ids
    assert res_692["wp2shell_vulnerable"] is True
    assert res_692["has_critical_cve"] is True

    # Test 6.8.3: vulnerable to CVE-2026-60137 only
    res_683 = check_wp_cves("6.8.3")
    cve_ids_683 = [c["cve"] for c in res_683["cves"]]
    assert "CVE-2026-60137" in cve_ids_683
    assert "CVE-2026-63030" not in cve_ids_683
    assert res_683["wp2shell_vulnerable"] is False

    # Test 6.9.5: Patched against both
    res_695 = check_wp_cves("6.9.5")
    assert len(res_695["cves"]) == 0
    assert res_695["wp2shell_vulnerable"] is False

    # Test 7.0.1: Vulnerable to both -> wp2shell
    res_701 = check_wp_cves("7.0.1")
    assert res_701["wp2shell_vulnerable"] is True
    assert len(res_701["cves"]) == 2

    # Test 7.0.2: Patched
    res_702 = check_wp_cves("7.0.2")
    assert len(res_702["cves"]) == 0


def test_two_phase_targets_and_storage():
    import os
    import tempfile
    from ip2domain.core.storage import StorageManager
    from ip2domain.modules.wp_hunter import WPHunter, normalize_discovered_domain

    assert normalize_discovered_domain("*.mycompany.com") == "mycompany.com"
    assert normalize_discovered_domain("eshdesign.ru:443") == "eshdesign.ru"
    assert normalize_discovered_domain("192.168.1.1") is None
    assert normalize_discovered_domain("localhost") is None

    # Test partition_targets
    raw = [
        "eshdesign.ru",
        "https://test.com/blog",
        "192.168.1.0/30",
        "8.8.8.8",
    ]
    direct, ip_specs, total_ips = WPHunter.partition_targets(raw, ports=[80, 443])
    # direct has eshdesign.ru (ports 80 and 443) + https://test.com/blog
    assert any(d["target"] == "eshdesign.ru" for d in direct)
    assert any(d["target"] == "test.com" for d in direct)
    # ip_specs has 192.168.1.0/30 (4 addresses) + 8.8.8.8 (1 address) = 5 total
    assert total_ips == 5

    # Test storage methods for wp_job_targets
    tmp = tempfile.mktemp(suffix=".db")
    try:
        storage = StorageManager(db_path=tmp)
        job_id = "test_phase_job"

        # Batch save
        targets_batch = [
            {"target": "site1.com", "source_ip": "1.2.3.4", "source_type": "ssl_san", "port": 443, "scheme": "https"},
            {"target": "site2.com", "source_ip": "1.2.3.4", "source_type": "ssl_san", "port": 80, "scheme": "http"},
            {"target": "site1.com", "source_ip": "1.2.3.4", "source_type": "ssl_san", "port": 443, "scheme": "https"}, # duplicate
        ]
        saved = storage.save_wp_job_targets_batch(job_id, targets_batch)
        assert storage.count_wp_job_targets(job_id, status="pending") == 2

        # Fetch pending
        pending = storage.get_pending_wp_job_targets(job_id, limit=10)
        assert len(pending) == 2
        p_ids = [p["id"] for p in pending]

        # Mark scanned
        storage.mark_wp_job_targets_scanned(p_ids)
        assert storage.count_wp_job_targets(job_id, status="pending") == 0
        assert storage.count_wp_job_targets(job_id, status="scanned") == 2
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


