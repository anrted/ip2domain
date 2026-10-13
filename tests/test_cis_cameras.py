"""Unit tests for CIS and Russian camera brand detection and stream path resolution."""
import pytest
from ip2domain.cameras.scanner_v2.protocols.rtsp import (
    _detect_brand_from_rtsp_text,
    _MACROSCOP_PATHS,
    _TRASSIR_PATHS,
    _RAYSHARP_PATHS,
    _TVT_PATHS,
    _IPEYE_PATHS,
    _SPUTNIK_PATHS,
)
from ip2domain.core.storage.scanner_v2 import classify_v2_device
from ip2domain.cameras.scanner_v2.aggregation import _is_camera_brand


def test_rtsp_brand_detection_cis_brands():
    assert _detect_brand_from_rtsp_text("Server: Macroscop RTSP Server") == "Macroscop"
    assert _detect_brand_from_rtsp_text("Server: Trassir RTSP/1.0") == "Trassir"
    assert _detect_brand_from_rtsp_text("DSSL RTSP Server") == "Trassir"
    assert _detect_brand_from_rtsp_text("Server: VeSta IPC RTSP") == "VeSta"
    assert _detect_brand_from_rtsp_text("Server: RaySharp RTSP Server") == "RaySharp"
    assert _detect_brand_from_rtsp_text("Server: Tantos DVR") == "Tantos"
    assert _detect_brand_from_rtsp_text("Server: Optimus NVR RTSP") == "Optimus"
    assert _detect_brand_from_rtsp_text("Server: Novicam RTSP") == "Novicam"
    assert _detect_brand_from_rtsp_text("Server: Satvision IP Cam") == "Satvision"
    assert _detect_brand_from_rtsp_text("Server: LTV-CCTV") == "LTV"
    assert _detect_brand_from_rtsp_text("Server: Polyvision NVR") == "Polyvision"
    assert _detect_brand_from_rtsp_text("Server: Smartec RTSP") == "Smartec"
    assert _detect_brand_from_rtsp_text("Server: IPEYE Streaming Server") == "IPEYE"
    assert _detect_brand_from_rtsp_text("Server: Sputnik Intercom") == "Sputnik"


def test_cis_rtsp_paths_presence():
    assert "/channel1" in _MACROSCOP_PATHS
    assert "/trassir-video/0" in _TRASSIR_PATHS
    assert "/ch0_0.264" in _RAYSHARP_PATHS
    assert "/ch01.264" in _TVT_PATHS
    assert "/live/ch0" in _IPEYE_PATHS
    assert "/live" in _SPUTNIK_PATHS


def test_device_classification_cis_brands():
    assert classify_v2_device(brand="Macroscop", title="Macroscop VMS") == "camera"
    assert classify_v2_device(brand="Trassir", title="TRASSIR Web") == "camera"
    assert classify_v2_device(brand="VeSta", title="VeSta IPC") == "camera"
    assert classify_v2_device(brand="DevLine", title="DevLine Линия") == "camera"
    assert classify_v2_device(brand="Si-Cam", title="Si-Cam IP Camera") == "camera"
    assert classify_v2_device(brand="Optimus", title="Optimus DVR") == "camera"
    assert classify_v2_device(brand="Satvision", title="Satvision NVR") == "camera"
    assert classify_v2_device(brand="Tantos", title="Tantos IPC") == "camera"
    assert classify_v2_device(brand="Novicam", title="Novicam Web") == "camera"
    assert classify_v2_device(brand="LTV", title="LTV Camera") == "camera"
    assert classify_v2_device(brand="Polyvision", title="Polyvision DVR") == "camera"
    assert classify_v2_device(brand="RaySharp", title="RaySharp DVR") == "camera"


def test_aggregation_is_camera_brand():
    for brand in [
        "Macroscop", "Trassir", "VeSta", "DevLine", "Si-Cam",
        "Optimus", "Satvision", "Tantos", "Novicam", "LTV",
        "Polyvision", "RaySharp", "Smartec", "IPEYE", "Sputnik"
    ]:
        assert _is_camera_brand(brand), f"{brand} should be recognized as a camera brand"
