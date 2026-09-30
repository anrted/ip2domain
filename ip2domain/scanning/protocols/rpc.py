"""Correlated ONC RPC NULL calls; no mount, enumeration or file access."""
import secrets
import struct

from ..detection.wire import WireRequest


def rpc_request(program, version, *, tcp=False):
    xid = secrets.randbits(32)
    # CALL, RPC v2, NULL procedure, AUTH_NONE credentials/verifier.
    payload = struct.pack("!10I", xid, 0, 2, program, version, 0, 0, 0, 0, 0)
    if tcp:
        payload = struct.pack("!I", 0x80000000 | len(payload)) + payload

    def parse(data):
        if tcp:
            if len(data) < 4:
                return None
            marker = struct.unpack("!I", data[:4])[0]
            if not marker & 0x80000000 or marker & 0x7fffffff != len(data) - 4:
                return None
            data = data[4:]
        if len(data) < 24:
            return None
        response_xid, message_type, reply_status, flavor, length = struct.unpack("!5I", data[:20])
        if (response_xid, message_type, reply_status) != (xid, 1, 0):
            return None
        offset = 20 + ((length + 3) // 4) * 4
        if offset + 4 > len(data):
            return None
        status = struct.unpack("!I", data[offset:offset + 4])[0]
        # Program unavailable/version mismatch proves RPC, not the requested service.
        if status != 0:
            return None
        return {"program": program, "program_version": version, "procedure": "NULL"}

    return WireRequest(payload, parse, framing="rpc" if tcp else "datagram", limit=4096)
