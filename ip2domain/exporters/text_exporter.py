from typing import Dict, List, Optional
from tabulate import tabulate
from ip2domain.exporters.base import BaseExporter


class TextExporter(BaseExporter):
    def export(self, results: List[Dict[str, any]], output_file: Optional[str] = None) -> str:
        table_data = []
        for res in results:
            ip = res["ip"]
            domains = res.get("domains", [])
            total = res.get("total_domains", 0)

            if not domains:
                table_data.append([ip, 0, "No domains found"])
            else:
                domain_str = "\n".join(domains[:10])
                if len(domains) > 10:
                    domain_str += f"\n... (+{len(domains) - 10} more)"
                table_data.append([ip, total, domain_str])

        output = tabulate(table_data, headers=["IP Address", "Count", "Domains"], tablefmt="grid")

        if output_file:
            # Write clean plain list of domains to output file if text format selected
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)

        return output
