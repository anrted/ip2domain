import json
from typing import Dict, List, Optional
from ip2domain.exporters.base import BaseExporter


class JSONExporter(BaseExporter):
    def export(self, results: List[Dict[str, any]], output_file: Optional[str] = None) -> str:
        formatted = json.dumps(results, indent=2, ensure_ascii=False)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(formatted)
        return formatted
