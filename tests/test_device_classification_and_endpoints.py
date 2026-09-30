"""Comprehensive tests for universal device classification, signatures, and actionable endpoints."""
import pytest
from unittest.mock import MagicMock

from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.classification import classify
from ip2domain.scanning.classification_catalog import match_device_rule, SIGNATURE_RULES, CATEGORY_META
from ip2domain.scanning.enrichment.device_endpoints import synthesize_device_endpoints
from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.policies import ScanConfig


def test_signature_rules_coverage():
    # Guarantee that all requested categories have rules
    categories = {r.category for r in SIGNATURE_RULES}
    assert "industrial" in categories
    assert "energy" in categories
    assert "access" in categories
    assert "voice" in categories
    assert "workplace" in categories
    assert "iot" in categories
    assert "traffic" in categories
    assert "ip_kvm" in categories
    assert "network" in categories
    assert "telematics" in categories
    assert "specialized" in categories
    assert "medical" in categories


def test_classify_and_endpoints_siemens_plc():
    obs = EndpointObservation(
        network_id="local",
        ip="192.168.1.50",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "Siemens, SIMATIC, S7-1200",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    assert len(obs.classifications) >= 1
    assert any(c.get("vendor") == "Siemens" for c in obs.classifications)
    assert any(c.get("kind") == "plc" for c in obs.classifications)

    dev = obs.device_info
    assert dev["category"] == "industrial"
    assert dev["vendor"] == "Siemens"
    assert dev["type"] == "plc"
    assert "Portal.mwsl" in dev["web_url"]
    assert any(a["id"] == "web" for a in dev["actions"])


def test_classify_and_endpoints_apc_ups():
    obs = EndpointObservation(
        network_id="local",
        ip="10.0.0.100",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "APC Network Management Card / Smart-UPS 1500",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "energy"
    assert "APC" in dev["vendor"]
    assert dev["type"] == "ups"
    assert dev["web_url"].startswith("http://10.0.0.100:80")
    assert any(a["id"] == "web" for a in dev["actions"])


def test_classify_and_endpoints_beward_intercom():
    obs = EndpointObservation(
        network_id="local",
        ip="192.168.10.15",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "Beward DKS15120 Intercom Panel",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "access"
    assert dev["vendor"] == "Beward"
    assert dev["type"] == "doorphone"
    assert "/cgi-bin/images_cgi" in dev["snapshot_url"]
    assert any(a["id"] == "snapshot" for a in dev["actions"])
    assert any(a["id"] == "web" for a in dev["actions"])


def test_classify_and_endpoints_freepbx_voip():
    obs = EndpointObservation(
        network_id="local",
        ip="10.10.1.20",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "Apache",
                    "product": "FreePBX Asterisk PBX",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "voice"
    assert "FreePBX" in dev["vendor"]
    assert dev["type"] == "pbx"
    assert "/admin" in dev["web_url"]


def test_classify_and_endpoints_hp_printer():
    obs = EndpointObservation(
        network_id="local",
        ip="192.168.0.200",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "HP-ChaiSOE/1.0 (HP LaserJet Professional)",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "workplace"
    assert dev["vendor"] == "HP"
    assert dev["type"] == "printer"
    assert dev["web_url"].startswith("http://192.168.0.200:80")


def test_classify_and_endpoints_hwgroup_sensor():
    obs = EndpointObservation(
        network_id="local",
        ip="192.168.1.150",
        port=80,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "HW group Poseidon 3266",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "iot"
    assert dev["vendor"] == "HW group"
    assert dev["type"] == "sensor"
    assert "values.xml" in dev["telemetry_url"]
    assert any(a["id"] == "telemetry" for a in dev["actions"])


def test_classify_and_endpoints_idrac_kvm():
    obs = EndpointObservation(
        network_id="local",
        ip="10.20.30.40",
        port=443,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "https",
                "categories": ["web"],
                "attributes": {
                    "server": "Integrated Dell Remote Access Controller - iDRAC 8",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "ip_kvm"
    assert dev["vendor"] == "Dell"
    assert dev["type"] == "kvm"
    assert "start.html" in dev["web_url"]
    assert "redfish" in dev["api_url"]
    assert any(a["id"] == "api" for a in dev["actions"])


def test_classify_and_endpoints_orthanc_dicom():
    obs = EndpointObservation(
        network_id="local",
        ip="172.16.5.10",
        port=8042,
        transport="tcp",
        state="open",
        services=[
            {
                "protocol": "http",
                "categories": ["web"],
                "attributes": {
                    "server": "Orthanc 1.11.2",
                    "status_code": 200,
                },
            }
        ],
    )
    classify(obs)
    dev = obs.device_info
    assert dev["category"] == "medical"
    assert dev["type"] == "medical"
    assert "explorer.html" in dev["web_url"]


def test_persistence_category_filtering(tmp_path):
    repo = InventoryRepository(str(tmp_path / "test.db"))
    cfg = ScanConfig(targets="192.168.1.1", profile="inventory_safe")
    plan = cfg.plan()
    scan_id = repo.create(cfg, plan)

    # Insert two endpoints with different categories
    obs_plc = EndpointObservation(
        network_id="local", ip="192.168.1.10", port=80, transport="tcp", state="open",
        services=[{"protocol": "http", "attributes": {"server": "Siemens SIMATIC S7-1200"}}],
    )
    classify(obs_plc)

    obs_ups = EndpointObservation(
        network_id="local", ip="192.168.1.20", port=80, transport="tcp", state="open",
        services=[{"protocol": "http", "attributes": {"server": "APC Smart-UPS NMC"}}],
    )
    classify(obs_ups)

    import json
    with repo.connect() as db:
        db.execute(
            "INSERT INTO inventory_endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, "local", "192.168.1.10", "tcp", 80, "", "open", json.dumps(obs_plc.to_dict()), 100, 100),
        )
        db.execute(
            "INSERT INTO inventory_endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, "local", "192.168.1.20", "tcp", 80, "", "open", json.dumps(obs_ups.to_dict()), 100, 100),
        )

    # Query without filter: returns both
    all_ep = repo.endpoints(scan_id)
    assert len(all_ep) == 2

    # Query with category='industrial': returns only Siemens
    plc_ep = repo.endpoints(scan_id, category="industrial")
    assert len(plc_ep) == 1
    assert plc_ep[0]["device_info"]["vendor"] == "Siemens"

    # Query with category='energy': returns only APC
    ups_ep = repo.endpoints(scan_id, category="energy")
    assert len(ups_ep) == 1
    assert "APC" in ups_ep[0]["device_info"]["vendor"]
