"""RFC 3414 §4 SNMPv3 engine discovery, no community guesses or object reads."""
import secrets

from .ber import content, fields, integer, number, sequence, tlv
from ..detection.wire import WireRequest


def snmp_request():
    message_id, request_id = secrets.randbits(30), secrets.randbits(30)
    empty = tlv(4, b"")
    header = sequence(integer(message_id), integer(8192), tlv(4, b"\x04"), integer(3))
    security = sequence(empty, integer(0), integer(0), empty, empty, empty)
    pdu = tlv(0xa0, integer(request_id) + integer(0) + integer(0) + sequence())
    scoped = sequence(empty, empty, pdu)
    payload = sequence(integer(3), header, tlv(4, security), scoped)

    def parse(data):
        try:
            outer = fields(data)
            if len(outer) != 1:
                return None
            message = fields(content(outer[0], 0x30))
            if len(message) != 4 or number(message[0]) != 3:
                return None
            hdr = fields(content(message[1], 0x30))
            if len(hdr) != 4 or number(hdr[0]) != message_id or number(hdr[3]) != 3:
                return None
            flags = content(hdr[2], 4)
            if len(flags) != 1 or flags[0] & 3:
                return None
            security_outer = fields(content(message[2], 4))
            if len(security_outer) != 1:
                return None
            usm = fields(content(security_outer[0], 0x30))
            if len(usm) != 6:
                return None
            engine_id = content(usm[0], 4)
            if not 5 <= len(engine_id) <= 32:
                return None
            scoped_fields = fields(content(message[3], 0x30))
            if len(scoped_fields) != 3:
                return None
            report = fields(content(scoped_fields[2], 0xa8))
            if len(report) != 4 or number(report[0]) not in (0, request_id):
                return None
            if number(report[1]) != 0:
                return None
            return {"version": "3", "engine_id": engine_id.hex(), "discovery_only": True}
        except (ValueError, IndexError):
            return None

    return WireRequest(payload, parse, framing="datagram", limit=8192)
