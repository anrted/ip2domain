import ipaddress
import os
from typing import Tuple

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.core.verifier import DomainVerifier


def private_targets_allowed() -> bool:
    return os.environ.get("IP2DOMAIN_ALLOW_PRIVATE_TARGETS", "0").lower() in {"1", "true", "yes"}


async def validate_network_target(target: str, allow_unresolved_domain: bool = False) -> Tuple[bool, str]:
    """Reject malformed and non-public targets unless explicitly enabled by the operator."""
    value = target.strip()
    try:
        ip = ipaddress.ip_address(value)
        if not private_targets_allowed() and not ip.is_global:
            return False, "Private, loopback, link-local and reserved targets are disabled"
        return True, str(ip)
    except ValueError:
        pass

    domain = normalize_domain(value)
    if not domain:
        return False, "Invalid IP address or domain name"
    resolved = await DomainVerifier.resolve_domain(domain, timeout=5)
    if not resolved:
        if allow_unresolved_domain:
            return True, domain
        # Try resolving www.<domain> as fallback check
        if not domain.startswith("www."):
            www_resolved = await DomainVerifier.resolve_domain(f"www.{domain}", timeout=5)
            if www_resolved:
                if not private_targets_allowed():
                    for resolved_ip in www_resolved:
                        if not ipaddress.ip_address(resolved_ip).is_global:
                            return False, "Target resolves to a non-public address"
                return True, domain
        return False, "Target does not resolve"
    if not private_targets_allowed():
        for resolved_ip in resolved:
            if not ipaddress.ip_address(resolved_ip).is_global:
                return False, "Target resolves to a non-public address"
    return True, domain
