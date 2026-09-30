"""Explicit composition of native probes; capability reporting uses the same source."""
from .wire import WireProbe, WireRegistry, WireRequest
from ..protocols.binary import (
    coap_request, dns_request, mqtt_request, mqtt_response, sip_request,
    smb_request, smb_response, rdp_request, rdp_response,
    rtmp_request, rtmp_response,
    s7_request, s7_response, enip_request, enip_response,
    bacnet_request, bacnet_response,
)
from ..protocols.text import parse_response, request
from ..protocols.rpc import rpc_request
from ..protocols.ntp import ntp_request
from ..protocols.snmp import snmp_request
from ..protocols.opcua import opcua_request
from ..protocols.modbus import modbus_request


def _text(protocol):
    def build(observation, config):
        return WireRequest(
            request(protocol, observation.ip, observation.port, config.hostname),
            lambda data: parse_response(data, protocol),
        )
    return build


def _correlated(builder, transport):
    def build(observation, config):
        if builder is sip_request:
            packet, validate = builder(observation.ip, observation.port, transport=transport)
        else:
            packet, validate = builder()
        if builder is dns_request and transport == "tcp":
            packet = len(packet).to_bytes(2, "big") + packet
            original = validate
            validate = lambda data: len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2 and original(data[2:])
        framing = "dns" if builder is dns_request else "headers"
        return WireRequest(packet, lambda data: {} if validate(data) else None,
                           framing=framing if transport == "tcp" else "datagram")
    return build


from ..protocols import ipp, dicom
from ..protocols.industrial import dnp3, iec104, enip_identity
from ..protocols.media import srt
from ..protocols.discovery import ws_discovery, ssdp, mdns, iax, knx

def native_registry():
    probes = [
        WireProbe("ipp","tcp",("workplace",),ipp.request,(631,),"ipps"),
        WireProbe("dicom","tcp",("medical",),dicom.request,(104,11112)),
        WireProbe("dnp3", "tcp", ("industrial",), dnp3, (20000,)),
        WireProbe("iec-60870-5-104", "tcp", ("industrial",), iec104, (2404,)),
        WireProbe("srt", "udp", ("video",), srt, (9000,)),
        WireProbe("ws-discovery", "udp", ("video", "infrastructure"), ws_discovery, (3702,)),
        WireProbe("ssdp", "udp", ("iot", "infrastructure"), ssdp, (1900,)),
        WireProbe("mdns", "udp", ("infrastructure",), mdns, (5353,)),
        WireProbe("iax", "udp", ("voice",), iax, (4569,)),
        WireProbe("knx-ip", "udp", ("bms", "industrial"), knx, (3671,)),
        WireProbe("http", "tcp", ("web",), _text("http"), (80, 443, 8080, 8443), "https"),
        WireProbe("rtsp", "tcp", ("video",), _text("rtsp"), (554, 8554), "rtsps"),
        WireProbe("rtmp", "tcp", ("video",),
                  lambda o, c: WireRequest(rtmp_request(), rtmp_response, framing="fixed", minimum=3073, limit=3073),
                  (1935,), "rtmps"),
        WireProbe("mqtt", "tcp", ("iot",),
                  lambda o, c: WireRequest(mqtt_request(), mqtt_response, framing="fixed", minimum=4, limit=4),
                  (1883, 8883), "mqtts"),
        WireProbe("smb", "tcp", ("storage",),
                  lambda o, c: WireRequest(smb_request(), smb_response, framing="smb", minimum=8),
                  (445, 139)),
        WireProbe("rdp", "tcp", ("remote",),
                  lambda o, c: WireRequest(rdp_request(), rdp_response, framing="rdp", minimum=11),
                  (3389,)),
        WireProbe("sip", "tcp", ("voice",), _correlated(sip_request, "tcp"), (5060, 5061), "sips"),
        WireProbe("dns", "tcp", ("infrastructure",), _correlated(dns_request, "tcp"), (53,), "dot"),
        WireProbe("dns", "udp", ("infrastructure",), _correlated(dns_request, "udp"), (53,)),
        WireProbe("coap", "udp", ("iot",), _correlated(coap_request, "udp"), (5683,)),
        WireProbe("sip", "udp", ("voice",), _correlated(sip_request, "udp"), (5060,)),
        WireProbe("ntp", "udp", ("infrastructure",), lambda o, c: ntp_request(), (123,)),
        WireProbe("snmp", "udp", ("management",), lambda o, c: snmp_request(), (161,)),
        WireProbe("opc-ua", "tcp", ("industrial",), opcua_request, (4840,)),
        WireProbe("modbus-tcp", "tcp", ("industrial",), lambda o, c: modbus_request(c.modbus_unit_id), (502,)),
        WireProbe("s7comm", "tcp", ("industrial",),
                  lambda o, c: WireRequest(s7_request(), s7_response, framing="s7", minimum=7),
                  (102,)),
        WireProbe("enip", "tcp", ("industrial",),
                  lambda o, c: WireRequest(enip_request(), enip_identity, framing="enip", minimum=24),
                  (44818,)),
        WireProbe("bacnet", "udp", ("bms", "industrial"),
                  lambda o, c: WireRequest(bacnet_request(), bacnet_response, framing="datagram", minimum=4),
                  (47808,)),
    ]
    for transport in ("tcp", "udp"):
        for name, program, version, hints in (("rpcbind", 100000, 2, (111,)), ("nfs", 100003, 3, (2049,))):
            def build(o, c, program=program, version=version, transport=transport):
                return rpc_request(program, version, tcp=transport == "tcp")
            probes.append(WireProbe(name, transport, ("storage",), build, hints))
    return WireRegistry(probes)
