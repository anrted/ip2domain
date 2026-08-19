import ipaddress
import re
from typing import Generator, List, Union


class IPParser:
    """
    Parses and yields IP addresses from single IPs, CIDR ranges, range boundaries,
    and text files containing IP specifications.
    """

    DEFAULT_MAX_IPS = 1048576  # 1M IPs

    @staticmethod
    def parse_target(target: str, max_ips: int = DEFAULT_MAX_IPS) -> Generator[str, None, None]:
        """
        Parses a single target string (IP, CIDR, Range).
        Yields individual IP strings.
        """
        target = target.strip()
        if not target:
            return

        # Check for range pattern: e.g. 192.168.1.1-192.168.1.10
        range_match = re.match(r"^([\d\.]+)\s*-\s*([\d\.]+)$", target)
        if range_match:
            start_ip_str, end_ip_str = range_match.groups()
            try:
                start_ip = ipaddress.IPv4Address(start_ip_str)
                end_ip = ipaddress.IPv4Address(end_ip_str)
                if int(start_ip) > int(end_ip):
                    raise ValueError(f"Start IP ({start_ip}) is greater than end IP ({end_ip})")
                count = int(end_ip) - int(start_ip) + 1
                if max_ips and count > max_ips:
                    raise ValueError(f"Target expands to {count} IPs; maximum is {max_ips}")
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    yield str(ipaddress.IPv4Address(ip_int))
                return
            except ValueError as e:
                raise ValueError(f"Invalid IP range string '{target}': {e}") from e

        # Check for CIDR or Single IP via ipaddress module
        try:
            # Check CIDR
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                count = max(1, net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0))
                if max_ips and count > max_ips:
                    raise ValueError(f"Target expands to {count} IPs; maximum is {max_ips}")
                yielded = False
                for ip in net.hosts():
                    yielded = True
                    yield str(ip)
                if not yielded:
                    yield str(net.network_address)
            else:
                ip_obj = ipaddress.ip_address(target)
                yield str(ip_obj)
        except ValueError as e:
            raise ValueError(f"Could not parse IP target '{target}': {e}") from e

        # Empty generator fallback

    @classmethod
    def parse_targets(cls, targets: List[str]) -> Generator[str, None, None]:
        """
        Parses a list of target strings.
        Yields unique individual IP strings.
        """
        seen = set()
        for t in targets:
            for ip in cls.parse_target(t):
                if ip not in seen:
                    seen.add(ip)
                    yield ip

    @classmethod
    def parse_file(cls, filepath: str) -> Generator[str, None, None]:
        """
        Parses a file line-by-line containing IP specs.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        yield from cls.parse_targets(lines)
