"""Modbus 43/14 basic device identification; never reads/writes process registers."""
import secrets
import struct

from ..detection.wire import WireRequest
from ..inventory import public_text


def modbus_request(unit_id=1):
    transaction = secrets.randbits(16)
    pdu = b"\x2b\x0e\x01\x00"
    payload = struct.pack("!HHHB", transaction, 0, 1 + len(pdu), unit_id) + pdu

    def parse(data):
        if not 9 <= len(data) <= 260:
            return None
        tid, protocol, length, unit = struct.unpack("!HHHB", data[:7])
        if (tid, protocol, unit) != (transaction, 0, unit_id) or length != len(data) - 6:
            return None
        body = data[7:]
        if body[0] == 0xab and len(body) == 2 and body[1] in (1, 2, 3, 4, 6, 10, 11):
            return {"exception_code": body[1], "unit_id": unit}
        if len(body) < 7 or body[:3] != b"\x2b\x0e\x01" or body[4] not in (0, 255):
            return None
        if body[3] not in (1, 2, 3, 0x81, 0x82, 0x83):
            return None
        position, objects = 7, {}
        for _ in range(body[6]):
            if position + 2 > len(body):
                return None
            key, size = body[position:position + 2]
            position += 2
            if position + size > len(body):
                return None
            if key in (0, 1, 2):
                name = ("vendor", "product", "version")[key]
                objects[name] = public_text(body[position:position + size].decode("ascii", "replace"), 128)
            position += size
        if position != len(body):
            return None
        return {"unit_id": unit, "more_follows": bool(body[4]), **objects}

    return WireRequest(payload, parse, framing="modbus", limit=260)
