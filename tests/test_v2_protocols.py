"""Tests for Camera Scanner v2 Sofia and Dahua DHIP protocols."""
import pytest
from ip2domain.cameras.scanner_v2.protocols.sofia import (
    _pack_sofia_msg,
    _unpack_sofia_msg,
    MSG_LOGIN_REQ,
    MSG_LOGIN_RESP,
    MSG_SYSINFO_REQ,
)
from ip2domain.cameras.scanner_v2.protocols.dahua_media import probe_dahua_media


def test_pack_and_unpack_sofia_msg():
    payload = {"Name": "OPUserAuth", "SessionID": "0x00000000", "OPUserAuth": {"UserName": "admin", "Password": ""}}
    packed = _pack_sofia_msg(MSG_LOGIN_REQ, session_id=0, payload_json=payload, seq=1)

    assert len(packed) >= 20
    assert packed[0] == 0xFF  # Magic

    unpacked = _unpack_sofia_msg(packed)
    assert unpacked is not None
    msg_id, session_id, json_dict, _ = unpacked
    assert msg_id == MSG_LOGIN_REQ
    assert session_id == 0
    assert json_dict["Name"] == "OPUserAuth"
    assert json_dict["OPUserAuth"]["UserName"] == "admin"


def test_unpack_sofia_response():
    resp_json = {"Ret": 100, "SessionID": "0x00000002"}
    packed = _pack_sofia_msg(MSG_LOGIN_RESP, session_id=2, payload_json=resp_json)

    unpacked = _unpack_sofia_msg(packed)
    assert unpacked is not None
    msg_id, session_id, json_dict, _ = unpacked
    assert msg_id == MSG_LOGIN_RESP
    assert json_dict.get("Ret") == 100


def test_probe_dahua_media_unreachable():
    import asyncio
    # Test against unreachable port to ensure clean error handling
    res = asyncio.run(probe_dahua_media("127.0.0.1", port=59999))
    assert res["success"] is False
