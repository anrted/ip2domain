import logging
import os
from typing import List

import aiohttp

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.providers.base import BaseProvider


logger = logging.getLogger(__name__)


class ShodanProvider(BaseProvider):
    name = "shodan"
    description = "Shodan hostnames, domains and service banner names"
    requires_api_key = True

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        if not self.api_key:
            return []
        try:
            params = {"key": self.api_key}
            if os.environ.get("IP2DOMAIN_SHODAN_HISTORY", "0").lower() in {"1", "true", "yes"}:
                params["history"] = "true"
            async with session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params=params,
                timeout=15,
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug("Shodan error for %s: %s", ip, exc)
            return []

        values = [*(data.get("hostnames") or []), *(data.get("domains") or [])]
        for banner in data.get("data", []) or []:
            if isinstance(banner, dict):
                values.extend(banner.get("hostnames") or [])
                values.extend(banner.get("domains") or [])
                ssl_data = banner.get("ssl") or {}
                cert = ssl_data.get("cert") or {}
                values.extend(cert.get("subject", {}).values())
                san = cert.get("extensions", {}).get("subjectAltName", "")
                values.extend(san.split(",") if isinstance(san, str) else (san or []))
        found = set()
        for value in values:
            if not isinstance(value, (str, int)):
                continue
            candidate = str(value).strip()
            if candidate.upper().startswith("DNS:"):
                candidate = candidate[4:]
            domain = normalize_domain(candidate)
            if domain:
                found.add(domain)
        return sorted(found)
