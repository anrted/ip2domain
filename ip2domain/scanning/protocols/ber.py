"""Minimal bounded BER TLV helpers for SNMP discovery; no recursive decoding."""


def tlv(tag, payload):
    size = len(payload)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + payload


def integer(value):
    if not 0 <= value <= 0x7fffffff:
        raise ValueError("BER integer out of range")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(2, raw)


def sequence(*items):
    return tlv(0x30, b"".join(items))


def fields(data, limit=64):
    if len(data) > 8192:
        raise ValueError("BER size limit")
    offset = 0
    result = []
    while offset < len(data):
        if len(result) >= limit or len(data) - offset < 2:
            raise ValueError("invalid BER sequence")
        tag, length = data[offset:offset + 2]
        offset += 2
        if tag & 0x1f == 0x1f:
            raise ValueError("unsupported BER tag")
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 3 or offset + count > len(data):
                raise ValueError("invalid BER length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        if offset + length > len(data):
            raise ValueError("truncated BER")
        result.append((tag, data[offset:offset + length]))
        offset += length
    return result


def content(item, tag):
    if item[0] != tag:
        raise ValueError("unexpected BER tag")
    return item[1]


def number(item):
    raw = content(item, 2)
    if not 1 <= len(raw) <= 5:
        raise ValueError("invalid BER integer")
    return int.from_bytes(raw, "big", signed=True)
