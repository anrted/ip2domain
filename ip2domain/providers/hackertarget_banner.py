import logging
from typing import List

import aiohttp

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.providers.base import BaseProvider


logger = logging.getLogger(__name__)


class HackerTargetBannerProvider(BaseProvider):
    """Extract certificate names exposed by HackerTarget's banner lookup API."""

    name = "hackertarget_banner"
    description = "HackerTarget banner and TLS certificate hostname lookup"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        try:
            async with session.get(
                "https://api.hackertarget.com/bannerlookup/",
                params={"q": ip}, headers=headers, timeout=10,
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug("HackerTarget banner error for %s: %s", ip, exc)
            return []

        found = set()
        if isinstance(data, dict):
            for service in data.values():
                if not isinstance(service, dict):
                    continue
                values = [service.get("cn", ""), *service.get("alt_n", [])]
                for value in values:
                    domain = normalize_domain(value)
                    if domain:
                        found.add(domain)
        return sorted(found)
