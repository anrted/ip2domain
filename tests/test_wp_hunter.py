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
