"""Codec fixtures are constructed independently of parser internals."""
import asyncio
import struct
from types import SimpleNamespace

import pytest

from ip2domain.scanning.detection.catalog import native_registry
from ip2domain.scanning.detection.wire import WireRegistry
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.protocols.ber import fields, content, number, sequence, integer, tlv
from ip2domain.scanning.protocols.modbus import modbus_request
from ip2domain.scanning.protocols.ntp import ntp_request
from ip2domain.scanning.protocols.opcua import opcua_request
from ip2domain.scanning.protocols.rpc import rpc_request
from ip2domain.scanning.protocols.snmp import snmp_request
from ip2domain.scanning.transports.network import frame_complete


def test_port_hints_never_exclude_nonstandard_ports():
    registry = native_registry()
    ordinary = registry.select("tcp", 80)
    random_port = registry.select("tcp", 46321)
    assert {p.name for p in ordinary} == {p.name for p in random_port}
    assert registry.select("tcp", 502)[0].name == "modbus-tcp"
    assert [p.name for p in registry.select("tcp", 80, ("rtsp",))] == ["rtsp"]
    assert registry.select("tcp", 80, ()) == ()
    with pytest.raises(ValueError):
        WireRegistry((ordinary[0], ordinary[0]))


@pytest.mark.parametrize("tcp", [False, True])
def test_rpc_requires_correlated_success_not_program_unavailable(tcp):
    request = rpc_request(100003, 3, tcp=tcp)
    packet = request.payload[4:] if tcp else request.payload
    xid = struct.unpack("!I", packet[:4])[0]
    def response(status=0, transaction=xid):
        raw = struct.pack("!6I", transaction, 1, 0, 0, 0, status)
        return struct.pack("!I", len(raw) | 0x80000000) + raw if tcp else raw
    assert request.parse(response())["program"] == 100003
    assert request.parse(response(status=1)) is None
    assert request.parse(response(transaction=xid ^ 1)) is None
    assert request.parse(response()[:-1]) is None


def test_ntp_correlates_origin_timestamp():
    request = ntp_request()
    reply = bytearray(48)
    reply[0], reply[1] = 0x24, 2
    reply[24:32] = request.payload[40:48]
    assert request.parse(reply) == {"version": 4, "stratum": 2}
    reply[24] ^= 1
    assert request.parse(reply) is None


def test_snmp_engine_discovery_accepts_only_correlated_report():
    request = snmp_request()
    message = fields(content(fields(request.payload)[0], 0x30))
    msg_id = number(fields(content(message[1], 0x30))[0])
    scoped = fields(content(message[3], 0x30))
    request_id = number(fields(content(scoped[2], 0xa0))[0])
    empty = tlv(4, b"")
    def report(message_id=msg_id, pdu_tag=0xa8):
        header = sequence(integer(message_id), integer(8192), tlv(4, b"\0"), integer(3))
        usm = sequence(tlv(4, b"\x80\x00\x00\x01\x05"), integer(1), integer(20), empty, empty, empty)
        pdu = tlv(pdu_tag, integer(request_id) + integer(0) + integer(0) + sequence())
        return sequence(integer(3), header, tlv(4, usm), sequence(empty, empty, pdu))
    assert request.parse(report())["engine_id"] == "8000000105"
    assert request.parse(report(message_id=msg_id ^ 1)) is None
    assert request.parse(report(pdu_tag=0xa2)) is None
    assert request.parse(report()[:-1]) is None
    assert request.parse(b"\x30\x80") is None


def test_modbus_read_device_identification_and_exception():
    request = modbus_request(7)
    transaction = struct.unpack("!H", request.payload[:2])[0]
    def reply(pdu, tid=transaction):
        return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 7) + pdu
    pdu = b"\x2b\x0e\x01\x01\x00\x00\x02\x00\x03ABC\x01\x03PLC"
    assert request.parse(reply(pdu))["vendor"] == "ABC"
    assert request.parse(reply(pdu))["product"] == "PLC"
    assert request.parse(reply(pdu, tid=transaction ^ 1)) is None
    assert request.parse(reply(pdu[:-1])) is None
    assert request.parse(reply(b"\xab\x01"))["exception_code"] == 1
    assert request.parse(reply(b"\xab\xff")) is None


def test_opcua_ack_and_fragment_detection():
    request = opcua_request(EndpointObservation("192.0.2.1", 41824, "tcp"), SimpleNamespace(hostname=""))
    assert request.payload.startswith(b"HELF")
    reply = b"ACKF" + struct.pack("<6I", 28, 0, 8192, 8192, 8192, 1)
    assert request.parse(reply)["handshake_only"]
    assert request.parse(reply[:-1]) is None
    assert not frame_complete(reply[:12], "opcua")
    assert frame_complete(reply, "opcua")
    assert not frame_complete(b"\x20\x02\x00", "fixed", 4)
    assert frame_complete(b"\x20\x02\x00\x00", "fixed", 4)


def test_policy_excludes_industrial_traffic_without_additional_consent(monkeypatch):
    from ip2domain.scanning.detection.scheduler import run_wire_probes
    from ip2domain.scanning.policies import ScanConfig
    from ip2domain.scanning.transports.network import NetworkBudget
    async def forbidden(*args, **kwargs):
        pytest.fail("industrial probe sent without industrial_consent")
    monkeypatch.setattr("ip2domain.scanning.detection.scheduler.exchange", forbidden)
    config = ScanConfig(
        targets="192.0.2.1", profile="deep_identification", active_consent=True,
        enabled_probes=("modbus-tcp", "opc-ua"),
    )
    observation = EndpointObservation("192.0.2.1", 502, "tcp", state="open")
    asyncio.run(run_wire_probes(observation, NetworkBudget(config, config.plan().scope)))
    assert [a["status"] for a in observation.attempts] == ["skipped_policy", "skipped_policy"]
