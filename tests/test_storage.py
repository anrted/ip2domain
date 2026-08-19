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


def test_provider_neutral_catalog_namespaces_external_ids(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "catalog.db"))
    storage.save_cameras("centra", [{"id": "I-1-1", "title": "Centra"}])
    storage.save_cameras("generic-ip", [{"external_id": "I-1-1", "title": "IP camera"}])

    page = storage.list_cameras(limit=10)

    assert page["total"] == 2
    assert storage.get_camera("centra", "I-1-1")["title"] == "Centra"
    assert storage.get_camera("generic-ip", "I-1-1")["title"] == "IP camera"
    assert storage.get_camera("centra", "I-1-1")["uid"] != storage.get_camera("generic-ip", "I-1-1")["uid"]


def test_camera_device_can_be_loaded_directly_for_connection(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "camera-connect.db"))
    storage.save_camera_devices([{"target": "203.0.113.8", "score": 90, "services": []}])
    assert storage.get_camera_device("203.0.113.8")["score"] == 90
    assert storage.get_camera_device("203.0.113.9") is None


def test_legacy_centra_writes_are_projected_to_catalog(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "compat.db"))
    storage.save_centra_cameras([{"id": "I-12-1", "title": "Legacy"}])
    assert storage.get_camera("centra", "I-12-1")["title"] == "Legacy"


def test_centra_geocode_coordinates_are_cached_by_address(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "geocode.db"))
    address = "Россия, Кемеровская область, Новокузнецк, ул. Тольятти, 2"
    storage.save_centra_coordinates(address, [53.75, 87.12])
    assert storage.get_centra_coordinates([address]) == {address: [53.75, 87.12]}


def test_centra_scan_checks_include_not_found_ids(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "checks.db"))
    storage.save_centra_scan_checks([
        {"camera_id": "I-10-1", "camera_type": "I", "building_id": 10, "entrance": 1, "found": True},
        {"camera_id": "I-10-2", "camera_type": "I", "building_id": 10, "entrance": 2, "found": False},
        {"camera_id": "G-10-1", "camera_type": "G", "building_id": 10, "entrance": 1, "found": False},
    ])
    assert set(storage.get_centra_checked_ids("I", 10, 10, 1, 3)) == {"I-10-1", "I-10-2"}


def test_centra_screenshot_page_is_paginated_and_filtered(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "screens.db"))
    storage.save_centra_cameras([
        {"id": "I-10-1", "camera_type": "I", "available": True},
        {"id": "G-11-1", "camera_type": "G", "available": True},
        {"id": "I-12-1", "camera_type": "I", "available": False},
    ])
    page = storage.list_centra_cameras_page(0, 100, "I")
    assert page["total"] == 1
    assert page["cameras"][0]["id"] == "I-10-1"
    assert storage.get_centra_camera("G-11-1")["camera_type"] == "G"


def test_centra_screenshot_page_searches_title_address_and_id_case_insensitively(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "screen-search.db"))
    storage.save_centra_cameras([
        {"id": "H-1185-3", "title": "40 лет ВЛКСМ 116а", "address": "Новокузнецк"},
        {"id": "I-20-1", "title": "Домофон Мира 2", "address": "Осинники"},
    ])
    assert storage.list_centra_cameras_page(search="влксм")["total"] == 1
    assert storage.list_centra_cameras_page(search="ОСИННИКИ")["cameras"][0]["id"] == "I-20-1"
    assert storage.list_centra_cameras_page(search="1185-3")["cameras"][0]["id"] == "H-1185-3"


def test_centra_screenshot_page_is_sorted_by_title_before_pagination(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "screen-order.db"))
    storage.save_centra_cameras([
        {"id": "I-30-1", "camera_type": "I", "available": True, "title": "Ясная 1"},
        {"id": "I-10-1", "camera_type": "I", "available": True, "title": "Абрикосовая 2"},
        {"id": "G-20-1", "camera_type": "G", "available": True, "title": "Мира 3"},
    ])
    page = storage.list_centra_cameras_page(0, 2)
    assert [camera["title"] for camera in page["cameras"]] == ["Абрикосовая 2", "Мира 3"]
    assert storage.list_centra_cameras_page(2, 2)["cameras"][0]["title"] == "Ясная 1"


def test_centra_screenshot_title_sort_is_natural_and_ignores_camera_id(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "natural-order.db"))
    storage.save_centra_cameras([
        {"id": "I-1-1", "available": True, "title": "Домофон Тольятти 43"},
        {"id": "I-9999-1", "available": True, "title": "Домофон Тольятти 2"},
        {"id": "I-2-1", "available": True, "title": "Домофон Тольятти 16"},
    ])
    titles = [camera["title"] for camera in storage.list_centra_cameras_page()["cameras"]]
    assert titles == ["Домофон Тольятти 2", "Домофон Тольятти 16", "Домофон Тольятти 43"]


def test_centra_person_results_are_persisted_updated_and_filtered(tmp_path):
    storage = StorageManager(db_path=str(tmp_path / "people.db"))
    storage.save_centra_person_result({
        "camera_id": "I-10-1", "camera_type": "I", "people_count": 2,
        "confidence": 0.8, "title": "Домофон Тестовый 1",
    })
    storage.save_centra_person_result({
        "camera_id": "H-20-1", "camera_type": "H", "people_count": 1,
        "confidence": 0.7, "title": "Камера Парковка",
    })
    storage.save_centra_person_result({
        "camera_id": "I-10-1", "camera_type": "I", "people_count": 3,
        "confidence": 0.9, "title": "Домофон Тестовый 1",
    })

    all_results = storage.list_centra_person_results()
    filtered = storage.list_centra_person_results(camera_type="I", search="Тестовый")

    assert all_results["total"] == 2
    assert filtered["total"] == 1
    assert filtered["cameras"][0]["people_count"] == 3
    assert filtered["cameras"][0]["detected_at"]


def test_centra_reid_state_survives_storage_reopen_and_can_be_cleared(tmp_path):
    db_path = str(tmp_path / "reid.db")
    storage = StorageManager(db_path=db_path)
    storage.save_centra_reid_states([{
        "person_id": "person-7", "vector": [0.1, 0.2], "colour_score": 0.3,
        "last_seen": 9999999999.0, "camera_id": "I-1-1", "observations": [],
    }])

    reopened = StorageManager(db_path=db_path)
    states = reopened.load_centra_reid_states(86400)

    assert states[0]["person_id"] == "person-7"
    assert reopened.get_centra_reid_state("person-7", 86400)["camera_id"] == "I-1-1"
    assert reopened.clear_centra_reid_states() == 1
    assert reopened.load_centra_reid_states(86400) == []
