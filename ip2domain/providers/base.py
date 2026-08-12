from abc import ABC, abstractmethod
from typing import List, Optional
import aiohttp


class BaseProvider(ABC):
    """
    Abstract base class for all reverse IP domain lookup providers.
    To add a new data provider:
    1. Inherit from BaseProvider
    2. Define name, description, and optional API key settings
    3. Implement lookup_async(ip, session)
    """

    name: str = "base"
    description: str = "Base provider class"
    requires_api_key: bool = False
    accepts_ip: bool = True

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    @abstractmethod
    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        """
        Asynchronously perform reverse IP lookup for a given IP address.
        Returns a list of domain names associated with the IP.
        """
        pass
