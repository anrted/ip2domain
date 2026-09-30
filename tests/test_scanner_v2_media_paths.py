"""Tests for automated media paths catalog, RTMP probing, and stream parity."""
import pytest
from unittest.mock import AsyncMock, patch

from ip2domain.scanning.protocols.binary import rtmp_request, rtmp_response
from ip2domain.scanning.detection.catalog import native_registry
from ip2domain.scanning.enrichment.media_catalog import (
    HLS_PATHS,
    MJPEG_PATHS,
    SNAPSHOT_PATHS,
    get_candidate_media_paths,
)
from ip2domain.scanning.enrichment.web import enrich_web, media_signature
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.cameras.scanner_v2.aggregation import universal_observation_to_camera_result


def test_rtmp_handshake_and_catalog():
    # RTMP request bytes
    req = rtmp_request()
    assert len(req) == 1537
    assert req[0] == 0x03  # C0 version

    # RTMP response
    resp = rtmp_response(b"\x03" + b"\x00" * 1536 + req[1:])
    assert resp is not None
    assert resp["protocol"] == "rtmp"

    # RTMP negative
    assert rtmp_response(b"\x00" * 10) is None

    # Registered in native registry
    reg = native_registry()
    rtmp_probes = [p for p in reg.probes if p.name == "rtmp"]
    assert len(rtmp_probes) == 1
    assert 1935 in rtmp_probes[0].port_hints


def test_media_catalog_contents():
    # Checks that all critical paths from Camera Scanner v2 are present
    assert "/live/index.m3u8" in HLS_PATHS
    assert "/hls/live.m3u8" in HLS_PATHS
    assert "/axis-cgi/mjpg/video.cgi" in MJPEG_PATHS
    assert "/ISAPI/Streaming/channels/101/httpPreview" in MJPEG_PATHS
    assert "/ISAPI/Streaming/channels/101/picture" in SNAPSHOT_PATHS
    assert "/snap.jpg" in SNAPSHOT_PATHS

    # Candidates helper
    candidates = get_candidate_media_paths(brand="hikvision")
    assert len(candidates) > 10
    assert "/live/index.m3u8" in candidates
    assert any("ISAPI" in p for p in candidates)


def test_media_signature_detection():
    class DummySample:
        def __init__(self, status, headers, body):
            self.status = status
            self.headers = headers
            self.body = body

    # HLS sample
    hls_sample = DummySample(200, {"content-type": "application/vnd.apple.mpegurl"}, b"#EXTM3U\n#EXT-X-VERSION:3\n")
    assert media_signature(hls_sample) == "hls"

    # MJPEG sample
    mjpeg_sample = DummySample(200, {"content-type": "multipart/x-mixed-replace; boundary=myboundary"}, b"--myboundary\r\n\xff\xd8\xff\xe0")
    assert media_signature(mjpeg_sample) == "mjpeg"

    # Snapshot sample
    snap_sample = DummySample(200, {"content-type": "image/jpeg"}, b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert media_signature(snap_sample) == "http_snapshot"


@pytest.mark.anyio
async def test_automated_media_enrichment():
    obs = EndpointObservation(
        network_id="local",
        ip="192.168.1.100",
        port=80,
        transport="tcp",
        state="open",
        services=[{"protocol": "http", "port": 80, "categories": ["web"], "attributes": {"server": "Hikvision-Webs"}}],
    )
    cfg = ScanConfig(targets="192.168.1.100", profile="camera_legacy", media_catalog=True)

    class DummyBudget:
        config = cfg

    class DummySample:
        def __init__(self, status, headers, body):
            self.status = status
            self.headers = headers
            self.body = body

    async def mock_http_sample(budget, observation, path, **kwargs):
        if path == "/live/index.m3u8":
            return DummySample(200, {"content-type": "application/vnd.apple.mpegurl"}, b"#EXTM3U\n#EXT-X-VERSION:3\n")
        elif path == "/ISAPI/Streaming/channels/101/picture":
            return DummySample(200, {"content-type": "image/jpeg"}, b"\xff\xd8\xff\xe0\x00\x10JFIF")
        return DummySample(404, {}, b"Not Found")

    with patch("ip2domain.scanning.enrichment.web.http_sample", side_effect=mock_http_sample):
        await enrich_web(obs, DummyBudget())

    # Check services were added automatically without user entering paths
    protocols = [s["protocol"] for s in obs.services]
    assert "hls" in protocols
    assert "http_snapshot" in protocols


def test_rtsp_and_rtmp_stream_parity():
    # RTSP observation on port 554
    obs_rtsp = {
        "ip": "10.0.0.5",
        "port": 554,
        "transport": "tcp",
        "state": "open",
        "services": [
            {
                "protocol": "rtsp",
                "categories": ["video"],
                "attributes": {
                    "server": "Hikvision RTSP Server",
                    "vendor": "Hikvision",
                },
            }
        ],
    }
    cam_rtsp = universal_observation_to_camera_result(obs_rtsp)
    assert cam_rtsp is not None
    assert cam_rtsp.brand == "Hikvision"
    assert cam_rtsp.rtsp_port == 554
    # Must contain Hikvision channel streams
    urls = [s.url for s in cam_rtsp.streams]
    assert any("/Streaming/Channels/101" in u for u in urls)
    assert any("/Streaming/Channels/102" in u for u in urls)

    # RTMP observation on port 1935
    obs_rtmp = {
        "ip": "10.0.0.6",
        "port": 1935,
        "transport": "tcp",
        "state": "open",
        "services": [
            {
                "protocol": "rtmp",
                "categories": ["video"],
                "attributes": {"server": "RTMP Media Server"},
            }
        ],
    }
    cam_rtmp = universal_observation_to_camera_result(obs_rtmp)
    assert cam_rtmp is not None
    assert "rtmp" in cam_rtmp.protocols
    assert cam_rtmp.rtmp_port == 1935
    rtmp_urls = [s.url for s in cam_rtmp.streams if s.stream_type == "rtmp"]
    assert len(rtmp_urls) >= 1
    assert any("rtmp://10.0.0.6:1935/live" in u for u in rtmp_urls)
