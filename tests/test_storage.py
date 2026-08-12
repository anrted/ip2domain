import os
import tempfile
from ip2domain.core.storage import StorageManager


def test_sqlite_storage_manager():
    with tempfile.NamedTemporaryFile("w+", suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        storage = StorageManager(db_path=db_path)
        
        # Save scan
        storage.save_scan(
            job_id="test1234",
            target="194.33.15.13",
            verify=True,
            nmap=False,
            total_ips=1,
            total_domains=14,
            results=[{"ip": "194.33.15.13", "domains": ["kg17.ru"]}],
            graph={"nodes": [], "edges": [], "stats": {}},
        )

        # Retrieve history
        history = storage.list_history()
        assert len(history) == 1
        assert history[0]["id"] == "test1234"
        assert history[0]["target"] == "194.33.15.13"

        # Retrieve single scan
        scan = storage.get_scan("test1234")
        assert scan is not None
        assert scan["target"] == "194.33.15.13"
        assert scan["results"][0]["domains"] == ["kg17.ru"]

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_global_graph_uses_latest_scan_for_same_target(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "latest.db"))
    storage.save_scan(
        job_id="old-scan",
        target="Example.COM",
        verify=True,
        nmap=False,
        total_ips=1,
        total_domains=2,
        results=[{"ip": "203.0.113.10", "domains": ["example.com", "old.example.com"]}],
        graph={"nodes": [], "edges": [], "stats": {}},
    )
    storage.save_scan(
        job_id="new-scan",
        target="example.com",
        verify=True,
        nmap=False,
        total_ips=1,
        total_domains=1,
        results=[{"ip": "203.0.113.10", "domains": ["example.com"]}],
        graph={"nodes": [], "edges": [], "stats": {}},
    )

    global_results = storage.get_global_scan_results()

    assert len(storage.list_history()) == 2
    assert global_results == [{
        "ip": "203.0.113.10",
        "domains": ["example.com"],
        "provider_details": {},
        "open_ports": [],
        "nmap_status": "",
        "nmap_error": "",
        "nmap_hostname": "",
        "nmap_os": "",
        "nmap_tech_stack": [],
        "verified_live": False,
        "total_domains": 1,
    }]


def test_different_targets_preserve_independent_domains_for_same_ip(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "latest-ip.db"))
    storage.save_scan(
        job_id="domain-scan",
        target="example.com",
        verify=True,
        nmap=False,
        total_ips=1,
        total_domains=2,
        results=[{"ip": "203.0.113.10", "domains": ["example.com", "related.example.com"]}],
        graph={"nodes": [], "edges": [], "stats": {}},
    )
    storage.save_scan(
        job_id="ip-scan",
        target="203.0.113.10",
        verify=True,
        nmap=False,
        total_ips=1,
        total_domains=1,
        results=[{"ip": "203.0.113.10", "domains": ["example.com"]}],
        graph={"nodes": [], "edges": [], "stats": {}},
    )

    assert storage.get_global_scan_results()[0]["domains"] == [
        "example.com", "related.example.com"
    ]


def test_successful_nmap_rescan_can_clear_stale_open_ports(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "nmap-refresh.db"))
    base = {"ip": "8.8.8.8", "domains": ["dns.google"], "nmap_status": "completed"}
    storage.save_scan("old", "8.8.8.8", True, True, 1, 1,
                      [{**base, "open_ports": [{"port": 443, "service": "https"}]}],
                      {"nodes": [], "edges": [], "stats": {}})
    storage.save_scan("new", "8.8.8.8", True, True, 1, 1,
                      [{**base, "open_ports": []}],
                      {"nodes": [], "edges": [], "stats": {}})

    result = storage.get_global_scan_results()[0]
    assert result["open_ports"] == []
    assert result["nmap_status"] == "completed"


def test_camera_results_are_accumulated_and_updated_in_sqlite(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "cameras.db"))
    storage.save_camera_devices([{
        "target": "203.0.113.10", "hostname": "cam01.example", "score": 40,
        "confidence": "высокая", "findings": [], "services": [],
    }])
    storage.save_camera_devices([{
        "target": "203.0.113.11", "hostname": "nvr.example", "score": 80,
        "confidence": "очень высокая", "findings": [], "services": [],
    }, {
        "target": "203.0.113.10", "hostname": "camera01.example", "score": 75,
        "confidence": "очень высокая", "findings": [], "services": [],
    }])

    devices = storage.get_camera_devices()
    assert [item["target"] for item in devices] == ["203.0.113.11", "203.0.113.10"]
    assert devices[1]["hostname"] == "camera01.example"
    assert devices[1]["first_seen"]
    assert devices[1]["updated_at"]
    assert storage.clear_camera_devices() == 2
    assert storage.get_camera_devices() == []


def test_remote_desktop_results_are_accumulated_in_sqlite(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "remote.db"))
    storage.save_remote_desktop_services([{
        "target": "203.0.113.20", "port": 3389, "protocol_type": "rdp",
        "service": "ms-wbt-server", "scripts": [],
    }, {
        "target": "203.0.113.21", "port": 5900, "protocol_type": "vnc",
        "service": "vnc", "capture_id": "first", "scripts": [],
    }])
    storage.save_remote_desktop_services([{
        "target": "203.0.113.21", "port": 5900, "protocol_type": "vnc",
        "service": "vnc", "capture_id": "newer", "scripts": [],
    }])

    services = storage.get_remote_desktop_services()
    assert len(services) == 2
    vnc = next(item for item in services if item["protocol_type"] == "vnc")
    assert vnc["capture_id"] == "newer"
    assert vnc["first_seen"] and vnc["updated_at"]
    assert storage.clear_remote_desktop_services() == 2


def test_centra_cameras_are_persisted_and_updated(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "centra.db"))
    storage.save_centra_cameras([{
        "id": "I-374-1", "title": "Первое название", "embed_url": "https://example/embed"
    }])
    storage.save_centra_cameras([{
        "id": "I-374-1", "title": "Домофон Сибиряков-Гвардейцев 14", "video": {"width": 1920}
    }, {
        "id": "I-374-2", "title": "Второй подъезд"
    }])

    cameras = storage.get_centra_cameras()
    assert [camera["id"] for camera in cameras] == ["I-374-1", "I-374-2"]
    assert cameras[0]["title"] == "Домофон Сибиряков-Гвардейцев 14"
    assert cameras[0]["video"]["width"] == 1920
    assert cameras[0]["first_seen"] and cameras[0]["updated_at"]
    assert storage.clear_centra_cameras() == 2
