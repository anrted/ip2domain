"""Tests for Phase 1 Compatibility Bridge: UniversalObservation -> CameraResult and camera_legacy profile."""
import pytest
from unittest.mock import MagicMock

from ip2domain.cameras.scanner_v2.aggregation import (
    universal_observation_to_camera_result,
    project_observation_to_cameras,
)
from ip2domain.cameras.scanner_v2.models import CameraResult
from ip2domain.scanning.policies import ScanConfig, PROFILES, CAMERA_PORTS_STR
from ip2domain.scanning.inventory import EndpointObservation


def test_camera_legacy_profile_in_policies():
    assert "camera_legacy" in PROFILES
    assert PROFILES["camera_legacy"]["active"] is True

    cfg = ScanConfig(targets="192.0.2.1", profile="camera_legacy")
    assert cfg.profile == "camera_legacy"
    assert cfg.tcp_ports == CAMERA_PORTS_STR
    assert cfg.active_consent is True
    assert cfg.web_enrichment is True

    plan = cfg.plan()
    assert plan.endpoint_count > 0


def test_universal_observation_rtsp_on_non_standard_port():
    obs = {
        "ip": "192.0.2.55",
        "port": 8555,
        "transport": "tcp",
        "state": "open",
        "services": [
            {
                "protocol": "rtsp",
                "categories": ["video"],
                "attributes": {
                    "server": "Dahua RTSP Server",
                    "auth_required": True,
                    "status_code": 401,
                    "methods": "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY",
                },
            }
        ],
        "classifications": [],
        "attempts": [],
    }

    camera = universal_observation_to_camera_result(obs)
    assert camera is not None
    assert isinstance(camera, CameraResult)
    assert camera.ip == "192.0.2.55"
    assert camera.rtsp_port == 8555
    assert camera.brand == "Dahua"
    assert camera.auth_required is True
    assert "rtsp_direct" in camera.protocols
    assert len(camera.streams) >= 1
    assert any("8555" in s.url for s in camera.streams)
    assert all(s.auth_required for s in camera.streams)


def test_universal_observation_onvif_and_hikvision():
    obs = {
        "ip": "10.10.10.20",
        "port": 8000,
        "transport": "tcp",
        "state": "open",
        "services": [
            {
                "protocol": "hikvision_isapi",
                "categories": ["video", "web"],
                "attributes": {
                    "server": "Hikvision-Webs",
                    "model": "DS-2CD2043G0-I",
                    "serial": "DS-2CD2043G0-I20190101AAWR",
                    "version": "V5.5.82",
                    "snapshot_url": "http://10.10.10.20:8000/ISAPI/Streaming/channels/101/picture",
                },
            },
            {
                "protocol": "onvif",
                "categories": ["video"],
                "attributes": {
                    "rtsp_urls": ["rtsp://10.10.10.20:554/live/ch0"],
                },
            },
        ],
        "classifications": [
            {"kind": "camera", "evidence": ["hikvision:product:ds-2cd"], "confidence": 0.95}
        ],
    }

    camera = universal_observation_to_camera_result(obs)
    assert camera is not None
    assert camera.ip == "10.10.10.20"
    assert camera.brand == "Hikvision"
    assert camera.model == "DS-2CD2043G0-I"
    assert camera.serial == "DS-2CD2043G0-I20190101AAWR"
    assert camera.firmware == "V5.5.82"
    assert "hikvision_isapi" in camera.protocols
    assert "onvif" in camera.protocols
    assert any(s.stream_type == "http_snapshot" for s in camera.streams)
    assert any(s.url == "rtsp://10.10.10.20:554/live/ch0" for s in camera.streams)


def test_universal_observation_web_media_hls_mjpeg():
    obs = EndpointObservation(
        ip="192.168.1.100",
        port=8080,
        transport="tcp",
        state="open",
    )
    obs.service(
        "hls", categories=("video",),
        path="/live/playlist.m3u8", transport_security=False,
    )

    camera = universal_observation_to_camera_result(obs)
    assert camera is not None
    assert camera.ip == "192.168.1.100"
    assert "hls" in camera.protocols
    assert camera.http_port == 8080
    assert any(s.stream_type == "hls" and s.url == "http://192.168.1.100:8080/live/playlist.m3u8" for s in camera.streams)


def test_non_camera_service_returns_none():
    ssh_obs = {
        "ip": "192.0.2.1",
        "port": 22,
        "transport": "tcp",
        "state": "open",
        "services": [
            {"protocol": "ssh", "categories": ["management"], "attributes": {"banner": "SSH-2.0-OpenSSH_8.9p1"}}
        ],
        "classifications": [],
    }
    assert universal_observation_to_camera_result(ssh_obs) is None

    modbus_obs = {
        "ip": "192.0.2.2",
        "port": 502,
        "transport": "tcp",
        "state": "open",
        "services": [
            {"protocol": "modbus-tcp", "categories": ["industrial"], "attributes": {"unit_id": 1}}
        ],
        "classifications": [],
    }
    assert universal_observation_to_camera_result(modbus_obs) is None


def test_project_observation_to_cameras_calls_storage():
    mock_storage = MagicMock()
    obs = {
        "ip": "192.0.2.77",
        "port": 554,
        "transport": "tcp",
        "state": "open",
        "services": [
            {"protocol": "rtsp", "categories": ["video"], "attributes": {"auth_required": False}}
        ],
        "classifications": [],
    }

    camera = project_observation_to_cameras(obs, storage=mock_storage)
    assert camera is not None
    assert camera.ip == "192.0.2.77"

    # Verifies both tables get updated
    mock_storage.save_v2_result.assert_called_once()
    saved_v2_arg = mock_storage.save_v2_result.call_args[0][0]
    assert saved_v2_arg["ip"] == "192.0.2.77"
    assert "rtsp_direct" in saved_v2_arg["protocols"]

    mock_storage.save_camera_devices.assert_called_once()
    saved_dev_arg = mock_storage.save_camera_devices.call_args[0][0]
    assert len(saved_dev_arg) == 1
    assert saved_dev_arg[0]["target"] == "192.0.2.77"


def test_smb_and_rdp_probes_registered():
    from ip2domain.scanning.detection.catalog import native_registry
    registry = native_registry()
    names = {p.name for p in registry.probes}
    assert "smb" in names
    assert "rdp" in names

    # Verify SMB can be selected on non-standard port 3389
    probes_3389 = registry.select("tcp", 3389)
    assert any(p.name == "smb" for p in probes_3389)
    assert any(p.name == "rdp" for p in probes_3389)

    # Verify RDP can be selected on non-standard port 445 or 22
    probes_22 = registry.select("tcp", 22)
    assert any(p.name == "smb" for p in probes_22)
    assert any(p.name == "rdp" for p in probes_22)


def test_smb_and_rdp_parsing():
    from ip2domain.scanning.protocols.binary import smb_response, rdp_response, smb_request, rdp_request

    # Test SMB2 response parsing
    mock_smb_resp = b"\x00\x00\x00\x48\xfeSMB" + b"\x00" * 60 + b"\x02\x02" + b"\x00" * 10
    parsed_smb = smb_response(mock_smb_resp)
    assert parsed_smb is not None
    assert "Microsoft Windows / Samba SMB" in parsed_smb["server"]
    assert "2.0.2" in parsed_smb["dialect"]

    # Test RDP response parsing
    mock_rdp_resp = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x03\x00\x00\x00"
    parsed_rdp = rdp_response(mock_rdp_resp)
    assert parsed_rdp is not None
    assert "RDP" in parsed_rdp["server"]
    assert parsed_rdp["ssl_supported"] is True


def test_full_tcp_plan_prioritizes_base_ports():
    from ip2domain.scanning.policies import ScanConfig
    config = ScanConfig(targets="192.168.1.1", profile="full_tcp", prioritize_base_ports=True, block_size=32)
    plan = config.plan()

    assert plan.endpoint_count == 65535
    first_block = plan.block(0)
    # The first block should contain base priority ports (80, 443, 554, 22, 445, 3389, etc.)
    assert 80 in first_block.ports
    assert 443 in first_block.ports
    assert 22 in first_block.ports
    assert 445 in first_block.ports
    assert 3389 in first_block.ports
    assert 554 in first_block.ports

    # Verify all 65535 ports are present without duplication
    all_ports = []
    for i in range(len(plan.blocks)):
        all_ports.extend(plan.blocks[i][1])
    assert len(all_ports) == 65535
    assert len(set(all_ports)) == 65535
    assert min(all_ports) == 1
    assert max(all_ports) == 65535
