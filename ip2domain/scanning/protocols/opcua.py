"""OPC UA Part 6 Hello/Acknowledge only; never opens a session or reads nodes."""
import struct

from ..detection.wire import WireRequest
from .text import authority


def opcua_request(observation, config):
    endpoint = f"opc.tcp://{authority(observation.ip, observation.port, config.hostname)}/".encode()
    body = struct.pack("<6I", 0, 8192, 8192, 8192, 1, len(endpoint)) + endpoint
    payload = b"HELF" + struct.pack("<I", len(body) + 8) + body

    def parse(data):
        if len(data) != 28 or data[:4] != b"ACKF" or struct.unpack("<I", data[4:8])[0] != len(data):
            return None
        version, receive, send, maximum, chunks = struct.unpack("<5I", data[8:])
        if version != 0 or receive < 8192 or send < 8192:
            return None
        return {"protocol_version": version, "handshake_only": True}

    return WireRequest(payload, parse, framing="opcua", limit=8192)
