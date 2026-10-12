"""Minimal discovery-only binary handshakes. No subscriptions or device writes."""
import secrets
import struct


def mqtt_request():
    client = ("scanner-" + secrets.token_hex(4)).encode()
    body = b"\x00\x04MQTT\x04\x02\x00\x05" + struct.pack("!H", len(client)) + client
    return b"\x10" + bytes([len(body)]) + body


def mqtt_response(data):
    if len(data) >= 4 and data[:2] == b"\x20\x02" and data[2] in (0, 1) and data[3] <= 5:
        return {"return_code": data[3], "auth_required": data[3] in (4, 5)}
    return None


def dns_request():
    transaction = secrets.token_bytes(2)
    # Root SOA, no recursion, no address expansion and no third-party hostname.
    packet = transaction + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x01"
    def match(data):
        if len(data) < 17 or data[:2] != transaction or not data[2] & 0x80:
            return False
        # A root SOA response must echo the question; matching an arbitrary
        # datagram's transaction ID/QR bit alone is too weak.
        return data[2] & 0x78 == 0 and data[4:6] == b"\x00\x01" and data[12:17] == packet[12:17]
    return packet, match


def coap_request():
    message_id = secrets.token_bytes(2)
    # Empty CoAP ping: no resource read/write. A correlated RST proves CoAP.
    packet = b"\x40\x00" + message_id
    return packet, lambda data: len(data) >= 4 and data[:2] == b"\x70\x00" and data[2:4] == message_id


def sip_request(ip, port, transport="udp"):
    call_id = secrets.token_hex(12)
    branch = "z9hG4bK" + secrets.token_hex(8)
    host = f"[{ip}]" if ":" in ip else ip
    packet = (
        f"OPTIONS sip:{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} 0.0.0.0;branch={branch};rport\r\n"
        f"From: <sip:scanner@invalid>;tag=scanner\r\nTo: <sip:{host}>\r\n"
        f"Call-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
    ).encode()
    def match(data):
        import re
        text = data.decode("ascii", "replace")
        return bool(
            re.match(r"SIP/2\.0 [1-6]\d\d ", text)
            and re.search(r"(?im)^Call-ID:\s*" + re.escape(call_id) + r"\s*$", text)
            and re.search(r"(?im)^CSeq:\s*1 OPTIONS\s*$", text)
        )
    return packet, match


def smb_request():
    header=struct.pack('<4sHHIHHIIQIIQ16s',b'\xfeSMB',64,0,0,0,1,0,0,1,0,0,0,b'\x00'*16)
    body=struct.pack('<HHHHI16sQ',36,2,1,0,0,secrets.token_bytes(16),0)+struct.pack('<HH',0x202,0x210)
    payload=header+body
    return b'\x00'+len(payload).to_bytes(3,'big')+payload


def smb_response(data):
    if len(data)<132 or data[4:8]!=b'\xfeSMB':return None
    if int.from_bytes(data[1:4],'big')+4!=len(data):return None
    if int.from_bytes(data[8:10],'little')!=64 or int.from_bytes(data[16:18],'little')!=0:return None
    if int.from_bytes(data[12:16],'little')!=0 or int.from_bytes(data[68:70],'little')!=65:return None
    dialect=int.from_bytes(data[72:74],'little')
    names={0x202:'2.0.2',0x210:'2.1',0x300:'3.0',0x302:'3.0.2',0x311:'3.1.1'}
    if dialect not in names:return None
    return dict(server="Microsoft Windows / Samba SMB",dialect='SMB '+names[dialect],version=names[dialect],server_guid=data[76:92].hex(),security_mode=int.from_bytes(data[70:72],'little'))


def rdp_request():
    return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"


def rdp_response(data):
    if len(data) >= 11 and data[0] == 0x03 and data[1] == 0x00 and data[5] == 0xd0:
        proto_flags = int.from_bytes(data[15:19], "little") if len(data) >= 19 else 0
        return {
            "server": "Microsoft Terminal Services / RDP",
            "ssl_supported": bool(proto_flags & 1),
            "credssp_supported": bool(proto_flags & 2),
        }
    return None


_RTMP_C1 = b"\x00" * 8 + secrets.token_bytes(1528)


def rtmp_request():
    return b"\x03" + _RTMP_C1


def rtmp_response(data):
    # A TCP echo / partial S1 is not a server handshake. S2 must echo
    # the client's timestamp and random data (its second timestamp differs).
    if (len(data) >= 3073 and data[0] == 3
            and data[1:1537] != _RTMP_C1
            and data[1537:1541] == _RTMP_C1[:4]
            and data[1545:3073] == _RTMP_C1[8:]):
        return {"protocol": "rtmp", "server": "RTMP Media Server"}
    return None


def s7_request():
    # COTP Connection Request (CR TPDU) for Siemens S7-300/400/1200/1500
    # TPKT (4 bytes: v3, res 0, len 22) + COTP CR (18 bytes)
    return b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"


def s7_response(data):
    # COTP Connection Confirm (CC TPDU)
    if len(data) >= 11 and data[0:2] == b"\x03\x00" and int.from_bytes(data[2:4], "big") == len(data) and data[5] == 0xd0:
        return {"protocol": "s7comm", "handshake": "COTP connection confirm", "probable_protocol": "s7comm", "vendor": "Siemens"}
    return None


def enip_request():
    # EtherNet/IP ListIdentity command (0x0063)
    return b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def enip_response(data):
    if len(data) >= 24 and data[0:2] == b"\x63\x00":
        status = int.from_bytes(data[8:12], "little")
        info = {"protocol": "enip", "server": "EtherNet/IP CIP Device", "vendor": "EtherNet/IP"}
        if status == 0 and len(data) > 30:
            printable = "".join(chr(b) for b in data[30:] if 32 <= b <= 126).strip()
            if printable:
                info["product"] = printable[:50]
        return info
    return None


def bacnet_request():
    # BACnet/IP Who-Is (BVLC Type 0x81, Function 0x0a Unicast, Length 12)
    return b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"


def bacnet_response(data):
    if len(data) >= 4 and data[0] == 0x81 and data[1] in (0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b):
        return {"protocol": "bacnet", "server": "BACnet/IP Building Automation Device"}
    return None
