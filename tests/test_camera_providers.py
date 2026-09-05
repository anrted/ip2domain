import pytest

from ip2domain.cameras.centra import CentraProvider
from ip2domain.cameras.generic_ip import GenericIPCameraProvider
from ip2domain.cameras.providers import ProviderRegistry
from ip2domain.cameras.services import SnapshotCache


def test_registry_exposes_provider_capabilities():
    registry = ProviderRegistry()
    registry.register(CentraProvider())
    registry.register(GenericIPCameraProvider())
    descriptions = {item["id"]: item for item in registry.describe()}
    assert "discovery" in descriptions["centra"]["capabilities"]
    assert "snapshot" in descriptions["generic-ip"]["capabilities"]


def test_centra_adapter_owns_protocol_specific_urls():
    camera = CentraProvider().normalize({
        "id": "I-41820-1", "stream_host": "flus4.mycentra.ru", "title": "Camera"
    })
    assert camera.provider_id == "centra"
    assert [endpoint.kind for endpoint in camera.endpoints] == ["snapshot", "hls", "hls", "embed"]
    assert camera.endpoints[0].url.endswith("/I-41820-1/preview.jpg")


def test_generic_ip_adapter_requires_explicit_ip_endpoints():
    provider = GenericIPCameraProvider()
    camera = provider.normalize({
        "external_id": "yard", "endpoints": [{"kind": "snapshot", "url": "http://192.0.2.10/frame.jpg"}]
    })
    assert camera.external_id == "yard"
    with pytest.raises(ValueError):
        provider.normalize({
            "external_id": "unsafe", "endpoints": [{"kind": "snapshot", "url": "http://example.com/frame.jpg"}]
        })


def test_snapshot_cache_keys_do_not_use_untrusted_external_id(tmp_path):
    cache = SnapshotCache(tmp_path)
    path = cache.path("generic-ip", "../../camera/one")
    assert path.is_relative_to(tmp_path)
    assert "camera" not in path.name


def test_orion_provider_normalize_and_capabilities():
    from ip2domain.cameras.orion import OrionProvider
    provider = OrionProvider()
    camera = provider.normalize({
        "id": "1", "title": "9 мая - Водопьянова", "latitude": 56.058, "longitude": 92.913
    })
    assert camera.provider_id == "orion"
    assert camera.external_id == "1"
    assert camera.latitude == 56.058
    assert camera.longitude == 92.913
    assert any(ep.kind == "hls" and "fluserver.orionnet.online" in ep.url for ep in camera.endpoints)
    assert provider.validate_url("http://fluserver.orionnet.online/cam1/index.m3u8") is True
    assert provider.validate_url("http://evil.com/cam1") is False


def test_a42_provider_normalize_and_capabilities():
    from ip2domain.cameras.a42 import A42Provider
    provider = A42Provider()
    camera = provider.normalize({
        "id": "40418", "city": "Новокузнецк", "title": "Новокузнецк, Рокоссовского",
        "coordinates": [53.9005, 87.1257], "sldp": "wss://roadcam02.video.goodline.info:443/main/rcam_45"
    })
    assert camera.provider_id == "a42"
    assert camera.external_id == "40418"
    assert camera.latitude == 53.9005
    assert camera.longitude == 87.1257
    assert any(ep.kind == "rtsp" for ep in camera.endpoints)
    assert provider.validate_url("wss://roadcam02.video.goodline.info:443/main/rcam_45") is True
    assert provider.validate_url("https://malicious.com/stream") is False
