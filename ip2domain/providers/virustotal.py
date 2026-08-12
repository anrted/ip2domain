import logging
from typing import List

import aiohttp

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.providers.base import BaseProvider


logger = logging.getLogger(__name__)


class VirusTotalProvider(BaseProvider):
    name = "virustotal"
    description = "VirusTotal historical and current IP resolutions"
    requires_api_key = True

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        if not self.api_key:
            return []
        headers = {"x-apikey": self.api_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        params = {"limit": 40}
        found = set()
        # Bound pagination to avoid unexpectedly exhausting API quotas.
        for _ in range(5):
            try:
                async with session.get(url, params=params, headers=headers, timeout=15) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json(content_type=None)
            except Exception as exc:
                logger.debug("VirusTotal error for %s: %s", ip, exc)
                break
            for item in data.get("data", []) if isinstance(data, dict) else []:
                attributes = item.get("attributes") or {}
                domain = normalize_domain(attributes.get("host_name"))
                if domain:
                    found.add(domain)
            next_url = (data.get("links") or {}).get("next") if isinstance(data, dict) else None
            if not next_url:
                break
            url, params = next_url, None
        return sorted(found)
