from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class BaseExporter(ABC):
    """
    Abstract base class for output exporters.
    """

    @abstractmethod
    def export(self, results: List[Dict[str, any]], output_file: Optional[str] = None) -> str:
        """
        Formats results into string format, optionally writing to a file if output_file is provided.
        Returns the formatted string.
        """
        pass
