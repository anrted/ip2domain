import logging
from typing import List

import aiohttp

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.providers.base import BaseProvider


logger = logging.getLogger(__name__)


class CensysProvider(BaseProvider):
    name = "censys"
    description = "Censys host names observed across Internet services"
    requires_api_key = True

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        if not self.api_key or ":" not in self.api_key:
            return []
        api_id, api_secret = self.api_key.split(":", 1)
        url = f"https://search.censys.io/api/v2/hosts/{ip}/names"
        params = {"per_page": 100}
        found = set()
        for _ in range(5):
            try:
                async with session.get(
                    url,
                    auth=aiohttp.BasicAuth(api_id, api_secret),
                    params=params,
                    timeout=15,
                ) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json(content_type=None)
            except Exception as exc:
                logger.debug("Censys error for %s: %s", ip, exc)
                break
            result = data.get("result", []) if isinstance(data, dict) else []
            if isinstance(result, dict):
                result = result.get("names", [])
            for value in result:
                domain = normalize_domain(value)
                if domain:
                    found.add(domain)
            next_url = (data.get("links") or {}).get("next") if isinstance(data, dict) else None
            if not next_url:
                break
            url, params = next_url, None
        return sorted(found)
