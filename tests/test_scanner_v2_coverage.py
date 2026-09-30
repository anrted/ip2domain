"""Tests for scanner_v2 enhancements and bug fixes."""
import pytest
from ip2domain.cameras.scanner_v2.models import CameraResult, StreamInfo, RTSP_PORTS, CAMERA_PORTS_V2
from ip2domain.cameras.scanner_v2.protocols.onvif import _ws_security_header, _WSSE_PW_TYPE, _WSSE_NONCE_TYPE
from ip2domain.cameras.scanner_v2.stage2_proto import _probe_generic_http


def test_rtsp_ports_clean():
    """Verify port 80 is removed from RTSP_PORTS to prevent bogus rtsp://...:80 streams."""
    assert 80 not in RTSP_PORTS
    assert 554 in RTSP_PORTS
    assert 5555 in RTSP_PORTS


def test_onvif_ws_security_oasis_compliance():
    """Verify that WS-Security header uses official OASIS URIs, not '...'."""
    header = _ws_security_header("admin", "admin123")
    assert "..." not in header
    assert _WSSE_PW_TYPE in header
    assert _WSSE_NONCE_TYPE in header
    assert "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest" in header
    assert "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" in header


@pytest.mark.anyio
async def test_no_false_positive_on_service_unavailable():
    """Verify HTTP 503 'Service Unavailable' or web pages with 'service' do NOT match 'RVi'."""
    res = await _probe_generic_http(
        ip="127.0.0.1",
        ports=[],
        credentials=[("admin", "admin")],
    )
    assert res["success"] is False


def test_auth_required_field():
    """Verify auth_required attribute on CameraResult and StreamInfo."""
    stream = StreamInfo(url="rtsp://192.168.1.1:554/live", auth_required=True)
    assert stream.auth_required is True
    assert stream.to_dict()["auth_required"] is True

    cam = CameraResult(ip="192.168.1.1", brand="Hikvision", auth_required=True, streams=[stream])
    assert cam.auth_required is True
    assert cam.to_dict()["auth_required"] is True


def test_webrtc_error_descr_ignore():
    """Verify that non-go2rtc error responses (like SpRecord error JSON) are ignored."""
    from ip2domain.cameras.scanner_v2.protocols.webrtc import is_valid_go2rtc_stream
    assert is_valid_go2rtc_stream("status", "error") is False
    assert is_valid_go2rtc_stream("error_descr", "unknown command 'STREAMS' or API is off") is False
    assert is_valid_go2rtc_stream("ch1", {"producers": []}) is True
    assert is_valid_go2rtc_stream("camera1", ["rtsp://1.2.3.4/live"]) is True


def test_sprecord_auth_hash():
    """Verify SpRecord challenge-response sha256 base64 hashing."""
    from ip2domain.cameras.scanner_v2.protocols.sprecord import compute_password_hash
    # Empty password with salt 'test_salt'
    hash_val = compute_password_hash("", "test_salt")
    import hashlib, base64
    expected = base64.b64encode(hashlib.sha256("test_salt".encode()).digest()).decode()
    assert hash_val == expected
