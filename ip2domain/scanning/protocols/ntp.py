"""NTP client time request, no mode-6/mode-7 administrative queries."""
import secrets

from ..detection.wire import WireRequest


def ntp_request():
    stamp = secrets.token_bytes(8)
    payload = b"\x23" + b"\x00" * 39 + stamp

    def parse(data):
        if len(data) < 48 or data[0] & 7 != 4 or (data[0] >> 3) & 7 not in (3, 4):
            return None
        if data[24:32] != stamp or data[1] > 16:
            return None
        return {"version": (data[0] >> 3) & 7, "stratum": data[1]}

    return WireRequest(payload, parse, framing="datagram", limit=512)
