import logging
from typing import List
from urllib.parse import urlsplit

import aiohttp

from ip2domain.core.domain_utils import normalize_domain
from ip2domain.providers.base import BaseProvider


logger = logging.getLogger(__name__)


class URLScanProvider(BaseProvider):
    name = "urlscan"
    description = "URLScan archived web scans by destination IP"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        headers = {"api-key": self.api_key} if self.api_key else {}
        try:
            async with session.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"ip:{ip}", "size": 100},
                headers=headers,
                timeout=12,
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug("URLScan error for %s: %s", ip, exc)
            return []

        found = set()
        for result in data.get("results", []) if isinstance(data, dict) else []:
            if not isinstance(result, dict):
                continue
            page = result.get("page") or {}
            task = result.get("task") or {}
            candidates = [page.get("domain"), task.get("domain")]
            for key in ("url", "redirected"):
                value = page.get(key) or task.get(key)
                if isinstance(value, str):
                    candidates.append(urlsplit(value).hostname)
            for value in candidates:
                domain = normalize_domain(value) if value else None
                if domain:
                    found.add(domain)
        return sorted(found)
