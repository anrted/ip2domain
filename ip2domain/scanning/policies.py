"""Explicit opt-in policy; broad port coverage is NOT permission for all probes."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re
from urllib.parse import unquote

from .scope import ScanPlan, TargetScope, parse_ports

COMMON_TCP = "21,22,23,25,53,80,110,111,135,139,143,443,445,554,631,993,995,1883,1935,3389,5000,8000,8080,8443,8554"
CAMERA_PORTS_STR = "80,81,88,322,443,554,555,1935,5544,5555,6554,7447,8000,8080,8081,8443,8554,8888,9000,9999,10554,34567,37777"
PROFILES = {
    "inventory_safe": {"active": False, "description": "TCP connect and server-first banners only"},
    "full_tcp": {"active": False, "description": "All TCP ports; server-first banners only"},
    "deep_identification": {"active": True, "description": "Opt-in application probes on any port"},
    "industrial_safe": {"active": False, "description": "Conservative connect/banner inventory; not risk-free"},
    "medical_safe": {"active": False, "description": "Conservative connect/banner inventory; not risk-free"},
    "camera_legacy": {"active": True, "description": "Camera Scanner v2 legacy profile; standard camera ports and video probes"},
}


@dataclass(frozen=True)
class ScanConfig:
    targets: str
    exclusions: str = ""
    profile: str = "inventory_safe"
    tcp_ports: str = COMMON_TCP
    udp_ports: str = ""
    network_id: str = "local"
    workers: int = 16
    per_host: int = 4
    per_subnet: int = 64
    rate: float = 200.0
    timeout: float = 1.0
    banner_timeout: float = 0.3
    endpoint_timeout: float = 30.0
    block_size: int = 32
    retries: int = 1
    active_consent: bool = False
    nmap: bool = False
    nmap_all_ports: bool = False
    nmap_timeout: float = 30.0
    hostname: str = ""
    max_endpoints: int = 5_000_000_000
    enabled_probes: tuple = None
    retain_all_states: bool = False
    industrial_consent: bool = False
    modbus_unit_id: int = 1
    web_enrichment: bool = False
    prioritize_base_ports: bool = False
    media_catalog: bool = False
    resource_paths: tuple = ("/",)
    execution_mode: str = "staged"
    discovery_workers: int = 16
    enrichment_workers: int = 4
    queue_capacity: int = 2048

    site_id: str = ""
    target_group: str = ""
    tags: tuple = ()
    comments: str = ""
    mode: str = ""
    protocol_families: tuple = ()
    max_candidates: int = 128
    max_channels: int = 16
    max_requests_per_host: int = 1024
    protocol_workers: int = 8
    endpoint_workers: int = 4
    max_connections: int = 0
    per_host_rate: float = 20.0
    per_protocol_rate: float = 50.0
    allow_credentials: bool = False
    read_only: bool = True
    dnp3_address: int = 1
    dicom_ae_title: str = "ANY-SCP"
    icmp_discovery: bool = False
    reverse_dns: bool = False
    passive_interface: str = ""
    passive_seconds: float = 5.0

    def __post_init__(self):
        if not isinstance(self.dicom_ae_title,str) or not 1<=len(self.dicom_ae_title)<=16 or not self.dicom_ae_title.isascii():raise ValueError("invalid DICOM AE title")
        if type(self.icmp_discovery) is not bool or type(self.reverse_dns) is not bool:raise ValueError("invalid discovery switches")
        if not isinstance(self.passive_interface,str) or (self.passive_interface and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}',self.passive_interface)):raise ValueError("invalid passive interface")
        if not isinstance(self.passive_seconds,(int,float)) or not math.isfinite(self.passive_seconds) or not 0.1<=self.passive_seconds<=60:raise ValueError("invalid passive capture duration")
        if self.max_connections == 0:object.__setattr__(self,"max_connections",self.workers)
        if type(self.dnp3_address) is not int or not 0<=self.dnp3_address<65520: raise ValueError("invalid DNP3 address")
        if self.read_only is not True: raise ValueError("only read-only scans are supported")
        if type(self.allow_credentials) is not bool: raise ValueError("allow_credentials must be boolean")
        for key in ("site_id", "target_group", "comments", "mode"):
            if not isinstance(getattr(self,key),str) or len(getattr(self,key))>4096: raise ValueError("invalid "+key)
        for key in ("tags", "protocol_families"):
            if not isinstance(getattr(self,key),(tuple,list)) or any(not isinstance(v,str) or len(v)>100 for v in getattr(self,key)):raise ValueError("invalid "+key)
            object.__setattr__(self,key,tuple(getattr(self,key)))
        if self.mode:
            from .scan_modes import apply_mode
            apply_mode(self)

        for name in ("targets", "exclusions", "profile", "tcp_ports", "udp_ports", "network_id", "hostname"):
            if type(getattr(self, name)) is not str:
                raise ValueError(f"{name} must be a string")
        if len(self.targets) > 100_000 or len(self.exclusions) > 100_000:
            raise ValueError("scope input too large")
        if self.profile not in PROFILES:
            raise ValueError("unknown profile")
        if self.execution_mode not in ("staged", "sequential"):
            raise ValueError("unknown execution_mode")
        for name, low, high in (
            ("workers", 1, 128), ("per_host", 1, 32), ("per_subnet", 1, 128),
            ("block_size", 1, 256), ("retries", 0, 3),
            ("rate", 0.1, 10000), ("timeout", 0.05, 30),
            ("banner_timeout", 0.01, 5), ("endpoint_timeout", 1, 180),
            ("nmap_timeout", 1, 120), ("max_endpoints", 1, 100_000_000_000),
            ("max_candidates",1,10000), ("max_channels",1,256), ("max_requests_per_host",1,100000), ("protocol_workers",1,128), ("endpoint_workers",1,32), ("max_connections",1,256), ("per_host_rate",.1,1000), ("per_protocol_rate",.1,10000),
            ("discovery_workers", 1, 128), ("enrichment_workers", 1, 16), ("queue_capacity", 1, 100_000),
        ):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"invalid {name}")
        for name in ("workers", "per_host", "per_subnet", "block_size", "retries", "max_endpoints",
                     "discovery_workers", "enrichment_workers", "queue_capacity", "max_candidates", "max_channels", "max_requests_per_host", "protocol_workers", "endpoint_workers", "max_connections"):
            if type(getattr(self, name)) is not int:
                raise ValueError(f"{name} must be an integer")
        for name in ("active_consent", "nmap", "nmap_all_ports", "retain_all_states", "industrial_consent", "web_enrichment", "prioritize_base_ports", "media_catalog"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,80}", self.network_id):
            raise ValueError("invalid network_id")
        if self.hostname and not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", self.hostname):
            raise ValueError("hostname must be an ASCII DNS name")
        if self.profile == "camera_legacy":
            if self.tcp_ports == COMMON_TCP:
                object.__setattr__(self, "tcp_ports", CAMERA_PORTS_STR)
            if not self.active_consent:
                object.__setattr__(self, "active_consent", True)
            if not self.web_enrichment:
                object.__setattr__(self, "web_enrichment", True)
            object.__setattr__(self, "media_catalog", True)
        if self.active and not self.active_consent:
            raise ValueError("active probes require explicit consent")
        if (self.udp_ports or self.nmap or self.nmap_all_ports) and not self.active:
            raise ValueError("UDP and nmap require deep_identification")
        if self.nmap_all_ports and not self.nmap:
            raise ValueError("nmap_all_ports requires nmap")
        if type(self.modbus_unit_id) is not int or not 1 <= self.modbus_unit_id <= 247:
            raise ValueError("modbus_unit_id must be within 1-247; broadcasts are not allowed")
        if self.industrial_consent and not self.active:
            raise ValueError("industrial_consent requires an active profile")
        if self.web_enrichment and not self.active:
            raise ValueError("web_enrichment requires an active profile")
        if not isinstance(self.resource_paths, (list, tuple)) or not 1 <= len(self.resource_paths) <= 64:
            raise ValueError("resource_paths must contain 1-64 origin-relative paths")
        for path in self.resource_paths:
            if not isinstance(path, str) or not re.fullmatch(r"/[!-~]{0,511}", path):
                raise ValueError("resource path must be ASCII without spaces or control characters")
            decoded = unquote(path)
            if decoded.startswith("//") or any(c in decoded for c in "?#\\") or any(ord(c) < 33 for c in decoded):
                raise ValueError("resource paths cannot contain authorities, queries, fragments or controls")
        object.__setattr__(self, "resource_paths", tuple(dict.fromkeys(self.resource_paths)))
        if self.enabled_probes is not None:
            from .detection.catalog import native_registry
            supported = {p.name for p in native_registry().probes}
            if not isinstance(self.enabled_probes, (tuple, list)) or any(
                not isinstance(p, str) or p not in supported for p in self.enabled_probes
            ):
                raise ValueError("enabled_probes must contain supported native probe identifiers")
            object.__setattr__(self, "enabled_probes", tuple(dict.fromkeys(self.enabled_probes)))

    @property
    def active(self):
        return PROFILES[self.profile]["active"]

    def plan(self):
        scope = TargetScope(self.targets, self.exclusions)
        tcp = parse_ports("1-65535" if self.profile == "full_tcp" else self.tcp_ports)
        udp = parse_ports(self.udp_ports)
        if not tcp and not udp:
            raise ValueError("select at least one port")
        # When sweeping a wide or full port range (or full_tcp profile), prioritize
        # common/base ports first across targets so essential services are discovered early.
        if self.prioritize_base_ports and len(tcp) > 100:
            base_priority = (
                80, 443, 554, 22, 445, 3389, 8080, 8443, 8554, 1883, 5060,
                21, 23, 25, 53, 110, 111, 135, 139, 143, 631, 993, 995,
                1935, 5000, 8000, 8081, 8888, 9000, 34567, 37777, 502, 4840,
                2049, 9999, 10554,
            )
            tcp_set = set(tcp)
            first_ports = tuple(p for p in base_priority if p in tcp_set)
            first_set = set(first_ports)
            remaining_ports = tuple(p for p in tcp if p not in first_set)
            tcp = first_ports + remaining_ports
        plan = ScanPlan(scope, tcp, udp, self.block_size, prioritize_base_ports=self.prioritize_base_ports)
        if plan.endpoint_count > self.max_endpoints:
            raise ValueError("scope exceeds max_endpoints")
        return plan

    def to_dict(self):
        return asdict(self)
