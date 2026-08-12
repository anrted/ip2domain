import csv
import io
from typing import Dict, List, Optional
from ip2domain.exporters.base import BaseExporter


class CSVExporter(BaseExporter):
    def export(self, results: List[Dict[str, any]], output_file: Optional[str] = None) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "Domain", "Providers"])

        for res in results:
            ip = res["ip"]
            domains = res.get("domains", [])
            provider_details = res.get("provider_details", {})

            if not domains:
                writer.writerow([ip, "", ""])
            else:
                for domain in domains:
                    found_by = [
                        pname for pname, pdomains in provider_details.items() if domain in pdomains
                    ]
                    writer.writerow([ip, domain, ";".join(found_by)])

        content = output.getvalue()

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)

        return content
