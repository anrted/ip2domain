import ipaddress
import re
from typing import Optional


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def normalize_domain(value: str) -> Optional[str]:
    """Return a canonical ASCII DNS hostname or ``None`` for unsafe/invalid input."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or any(ch in value for ch in "/:@?#\\\x00\r\n\t "):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        ascii_name = value.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if len(ascii_name) > 253 or "." not in ascii_name:
        return None
    labels = ascii_name.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        return None
    # A numeric-only final label is not a DNS hostname TLD.
    if labels[-1].isdigit():
        return None
    return ascii_name


def is_subdomain_of(hostname: str, apex: str) -> bool:
    return hostname == apex or hostname.endswith("." + apex)
