"""Validated, indexable IP/port ranges without expanding large networks."""
from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass


def _merge(intervals):
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _addresses(text):
    result = {4: [], 6: []}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for value in line.split(","):
            value = value.strip()
            if not value:
                continue
            if "-" in value:
                first, last = map(ipaddress.ip_address, re.split(r"\s*-\s*", value))
                if first.version != last.version or int(first) > int(last):
                    raise ValueError("invalid IP range")
            elif "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                first, last = network.network_address, network.broadcast_address
            else:
                first = last = ipaddress.ip_address(value)
            result[first.version].append((int(first), int(last)))
    return {version: _merge(ranges) for version, ranges in result.items()}


class TargetScope:
    def __init__(self, targets: str, exclusions: str = ""):
        include, exclude = _addresses(targets), _addresses(exclusions)
        self.ranges = []
        self.ends = []
        total = 0
        for version in (4, 6):
            for start, end in include[version]:
                fragments = [(start, end)]
                for lo, hi in exclude[version]:
                    next_fragments = []
                    for a, b in fragments:
                        if hi < a or lo > b:
                            next_fragments.append((a, b))
                        else:
                            if a < lo:
                                next_fragments.append((a, lo - 1))
                            if hi < b:
                                next_fragments.append((hi + 1, b))
                    fragments = next_fragments
                for a, b in fragments:
                    self.ranges.append((version, a, b))
                    total += b - a + 1
                    self.ends.append(total)
        self.count = total
        if not total:
            raise ValueError("scope is empty")
        # No implicit broadcast/multicast scanning or unspecified destinations.
        forbidden = _addresses("0.0.0.0\n224.0.0.0/4\n255.255.255.255\n::\nff00::/8")
        for version, a, b in self.ranges:
            if any(a <= hi and b >= lo for lo, hi in forbidden[version]):
                raise ValueError("exclude unspecified, multicast and limited-broadcast addresses")

    def address(self, index: int) -> str:
        if not 0 <= index < self.count:
            raise IndexError(index)
        position = bisect.bisect_right(self.ends, index)
        version, start, _ = self.ranges[position]
        offset = index - (self.ends[position - 1] if position else 0)
        cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        return str(cls(start + offset))

    def contains(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip.version == version and a <= int(ip) <= b for version, a, b in self.ranges)


def parse_ports(expression: str):
    intervals = []
    for value in expression.split(","):
        value = value.strip()
        if not value:
            continue
        if not re.fullmatch(r"\d+(?:-\d+)?", value):
            raise ValueError("ports must be numbers or inclusive ranges")
        parts = value.split("-")
        first, last = int(parts[0]), int(parts[-1])
        if not 1 <= first <= last <= 65535:
            raise ValueError("port range must be within 1-65535")
        intervals.append((first, last))
    return tuple(p for lo, hi in _merge(intervals) for p in range(lo, hi + 1))


@dataclass(frozen=True)
class WorkBlock:
    ordinal: int
    ip: str
    transport: str
    ports: tuple


class ScanPlan:
    """Random-access work blocks: resume requires only a durable cursor."""
    def __init__(self, scope, tcp_ports, udp_ports, block_size=32, prioritize_base_ports=False):
        self.scope = scope
        self.prioritize_base_ports = bool(prioritize_base_ports)
        self.blocks = []
        for transport, ports in (("tcp", tcp_ports), ("udp", udp_ports)):
            for offset in range(0, len(ports), block_size):
                self.blocks.append((transport, tuple(ports[offset:offset + block_size])))
        self.total = scope.count * len(self.blocks)
        self.endpoint_count = scope.count * (len(tcp_ports) + len(udp_ports))

    def block(self, ordinal):
        if not 0 <= ordinal < self.total:
            raise IndexError(ordinal)
        if self.prioritize_base_ports:
            # First sweep base port blocks across ALL hosts, then sweep remaining blocks across ALL hosts
            port_index, host_index = divmod(ordinal, self.scope.count)
        else:
            host_index, port_index = divmod(ordinal, len(self.blocks))
        transport, ports = self.blocks[port_index]
        return WorkBlock(ordinal, self.scope.address(host_index), transport, ports)
