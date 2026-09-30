"""Camera profile contract tests, using no network and no production database."""
import asyncio
import subprocess
import sys
from unittest.mock import AsyncMock

import pytest

from ip2domain.cameras.scanner_v2 import stage2_proto
from ip2domain.cameras.scanner_v2.aggregation import merge_camera_results
from ip2domain.cameras.scanner_v2.profile import (
    build_camera_registry, camera_context, candidate_ports,
)

PROBES = {
    "onvif": "probe_onvif", "hikvision": "probe_hikvision",
    "dahua": "probe_dahua", "axis": "probe_axis", "hls": "probe_hls_mjpeg",
    "rtsp": "probe_rtsp_direct", "rtmp": "probe_rtmp", "webrtc": "probe_webrtc",
    "vms": "probe_vms", "sofia": "probe_sofia", "dahua_media": "probe_dahua_media",
    "sprecord": "probe_sprecord", "ingram": "probe_ingram", "generic": "_probe_generic_http",
}


@pytest.fixture
def probes(monkeypatch):
    mocks = {}
    for key, name in PROBES.items():
        mocks[key] = AsyncMock(return_value={"success": False})
        monkeypatch.setattr(stage2_proto, name, mocks[key])
    return mocks


@pytest.mark.parametrize("protocols", [None, []])
def test_default_profile_preserves_all_legacy_probes(probes, protocols):
    asyncio.run(stage2_proto.probe_host_v2("192.0.2.1", [80, 554, 1935], [], protocols))
    expected = set(PROBES) - {"sofia"}
    assert {key for key, mock in probes.items() if mock.await_count} == expected
    probes["rtmp"].assert_awaited_once_with("192.0.2.1", [1935])
    probes["rtsp"].assert_awaited_once_with("192.0.2.1", [554], [])


@pytest.mark.parametrize(
    "ports,protocols,expected",
    [
        ([80], ["rtsp"], {"sprecord", "ingram", "generic"}),
        ([554], ["rtsp"], {"rtsp", "sprecord", "ingram", "generic"}),
        ([34567], ["unknown"], {"sofia", "sprecord", "ingram", "generic"}),
        ([37777], ["unknown"], {"dahua_media", "sprecord", "ingram", "generic"}),
        ([80], ["xiongmai"], {"sofia", "sprecord", "ingram", "generic"}),
        ([80], ["dhip"], {"dahua_media", "sprecord", "ingram", "generic"}),
    ],
)
def test_filter_preserves_port_activation_and_always_on_probes(probes, ports, protocols, expected):
    asyncio.run(stage2_proto.probe_host_v2("192.0.2.1", ports, [], protocols))
    assert {key for key, mock in probes.items() if mock.await_count} == expected


def test_candidate_ports_preserve_custom_port_order():
    context = camera_context("192.0.2.1", [6020, 6010, 554, 1935], [])
    assert candidate_ports(context) == {
        "http": [6020, 6010], "rtsp": [554], "rtmp": [1935], "onvif": [6020, 6010],
    }


def test_neutral_empty_selection_differs_from_legacy_empty_filter(probes):
    from ip2domain.scanning import Endpoint, ProbeContext
    context = ProbeContext("192.0.2.1", (Endpoint(80),), enabled_probes=frozenset())
    selected = build_camera_registry(probes).select(context)
    assert [p.probe_id for p in selected] == ["sprecord", "ingram", "generic"]


def test_camera_projection_priority_and_auth(probes):
    probes["onvif"].return_value = {
        "success": True, "brand": "ONVIF Brand", "model": "A", "serial": "S",
        "firmware": "F", "onvif_port": 80,
        "rtsp_urls": ["rtsp://192.0.2.1/live"], "credentials": {"user": "operator"},
    }
    probes["hikvision"].return_value = {
        "success": True, "model": "B", "rtsp_urls": ["rtsp://192.0.2.1/live"],
        "snapshot_url": "http://192.0.2.1/snapshot", "auth_required": True,
    }
    camera = asyncio.run(stage2_proto.probe_host_v2("192.0.2.1", [554, 80], []))
    assert (camera.brand, camera.model, camera.serial, camera.firmware) == ("ONVIF Brand", "A", "S", "F")
    assert camera.protocols == ["onvif", "hikvision_isapi"]
    assert len(camera.streams) == 2
    assert camera.auth_required and not all(s.auth_required for s in camera.streams)
    assert camera.credentials == {"user": "operator"}
    assert camera.open_ports == [80, 554]


def test_sprecord_existing_result_is_preserved(probes):
    probes["sprecord"].return_value = {
        "success": True, "model": "Audio recorder", "firmware": "2",
        "http_port": 80, "auth_required": True,
        "streams": [{"url": "http://192.0.2.1/audio", "type": "http_audio"}],
    }
    camera = asyncio.run(stage2_proto.probe_host_v2("192.0.2.1", [80], []))
    assert camera.brand == "SpRecord"
    assert camera.protocols == ["sprecord_audio"]
    assert camera.streams[0].stream_type == "http_audio"
    assert camera.auth_required is True


def test_failed_probe_does_not_discard_successful_sibling(probes):
    probes["onvif"].side_effect = RuntimeError("private")
    probes["axis"].return_value = {"success": True, "mjpeg_url": "http://192.0.2.1/video"}
    camera = asyncio.run(stage2_proto.probe_host_v2("192.0.2.1", [80], []))
    assert camera.brand == "Axis"
    assert camera.streams[0].stream_type == "mjpeg"
    observation = asyncio.run(stage2_proto.probe_host_observation_v2("192.0.2.1", [80], []))
    assert observation.outcomes[0].status == "error"


@pytest.mark.parametrize("ports,brand", [([554], "Generic RTSP"), ([34599], "Xiongmai"), ([37777], "Dahua")])
def test_legacy_port_fallbacks(ports, brand):
    camera = merge_camera_results("192.0.2.1", ports, {})
    assert camera.brand == brand
    assert camera.streams
    assert camera.auth_required is None


def test_non_camera_is_not_added_to_legacy_camera_results():
    assert merge_camera_results("192.0.2.1", [80], {}) is None


def test_model_imports_do_not_initialize_scanner_engine():
    subprocess.run(
        [sys.executable, "-c", """
import sys
from ip2domain.scanning import ProbeRunner
from ip2domain.cameras.scanner_v2 import CameraResult
assert 'ip2domain.cameras.scanner_v2.engine' not in sys.modules
assert 'ip2domain.web.app' not in sys.modules
from ip2domain.cameras.scanner_v2.protocols import probe_axis
assert 'ip2domain.cameras.scanner_v2.protocols.rtsp' not in sys.modules
assert callable(probe_axis)
from ip2domain.cameras.scanner_v2 import run_v2_scan_pipeline
assert callable(run_v2_scan_pipeline)
"""],
        check=True, timeout=15,
    )


def test_existing_pipeline_uses_bounded_workers_and_persists_results(monkeypatch, tmp_path):
    from ip2domain.cameras.scanner_v2 import engine
    from ip2domain.cameras.scanner_v2.models import CameraResult, StreamInfo
    from ip2domain.core.storage import StorageManager

    async def scenario():
        active = peak = 0
        captured = []

        async def fingerprint(ip, ports, credentials, protocols=None):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.001)
                return CameraResult(
                    ip=ip, brand="Test", streams=[StreamInfo(f"rtsp://{ip}/live")],
                )
            finally:
                active -= 1

        async def capture(camera, capture_dir, **kwargs):
            captured.append(camera.ip)
            camera.streams[0].verified = True

        storage = StorageManager(str(tmp_path / "pipeline.db"))
        hosts = [(f"192.0.2.{i}", [554]) for i in range(1, 9)]
        monkeypatch.setattr(engine, "adaptive_port_sweep", AsyncMock(return_value=(hosts, "asyncio")))
        monkeypatch.setattr(engine, "probe_host_v2", fingerprint)
        monkeypatch.setattr(engine, "verify_camera_streams", capture)
        monkeypatch.setattr(engine.geo_city_db, "find_by_ip", lambda ip: None)
        job = engine.create_job("architecture-pipeline")
        try:
            await engine.run_v2_scan_pipeline(
                job.job_id, "192.0.2.1-192.0.2.8", local_discovery=False,
                stage2_concurrency=2, capture_dir=tmp_path, storage=storage,
            )
            assert job.status == "completed"
            assert peak == 2
            assert job.stage2_completed == job.stage3_completed == 8
            assert len(captured) == len(storage.get_v2_results()) == 8
            assert all(result["streams"][0]["verified"] for result in storage.get_v2_results())
            assert storage.get_v2_job(job.job_id)["status"] == "completed"
        finally:
            engine._ACTIVE_JOBS.pop(job.job_id, None)

    asyncio.run(scenario())
