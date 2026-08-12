from typing import Dict, List, Set, Tuple
from ip2domain.core.idn_utils import decode_punycode, format_domain_display


class GraphBuilder:
    """
    Constructs nodes and edges for network topology visualization:
    Relationship graph between IP addresses, Apex Domains, and Subdomains.
    Supports Punycode (xn--...) to Cyrillic IDN decoding.
    """

    @staticmethod
    def extract_apex_domain(domain: str) -> str:
        # Decode punycode before extracting apex domain
        domain_decoded = decode_punycode(domain)
        parts = domain_decoded.lower().split(".")
        if len(parts) <= 2:
            return domain_decoded.lower()
        # Common two-part TLDs (e.g. com.ua, co.uk, gov.ru, edu.ru, obl.ru)
        if len(parts) >= 3 and parts[-2] in {"com", "co", "gov", "edu", "org", "net", "oblmest", "obl"}:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @classmethod
    def build_graph(
        cls, scan_results: List[Dict[str, any]], hide_empty_ips: bool = True
    ) -> Dict[str, any]:
        """
        Converts lookup results into node-edge graph format for Vis.js / Cytoscape.js visualization.
        """
        nodes: List[Dict[str, any]] = []
        edges: List[Dict[str, any]] = []

        nodes_by_id: Dict[str, Dict[str, any]] = {}  # O(1) lookup by node id
        seen_edges: Set[Tuple[str, str, str]] = set()

        for item in scan_results:
            ip = item["ip"]
            domains = item.get("domains", [])
            open_ports = item.get("open_ports", [])
            verified = item.get("verified_live", False)

            # Skip empty IPs if hide_empty_ips is True
            if hide_empty_ips and not domains and not open_ports:
                continue

            ip_node_id = f"ip:{ip}"
            if ip_node_id not in nodes_by_id:
                ports_summary = ", ".join([f"{p['port']}/{p['service']}" for p in open_ports]) if open_ports else "None"
                ip_node = {
                    "id": ip_node_id,
                    "label": ip,
                    "group": "ip",
                    "shape": "diamond",
                    "color": "#f97316", # Vibrant Orange
                    "title": f"<b>IP:</b> {ip}<br><b>Verified:</b> {verified}<br><b>Open Ports:</b> {ports_summary}<br><b>Domains:</b> {len(domains)}",
                    "details": {
                        "ip": ip,
                        "open_ports": open_ports,
                        "nmap_status": item.get("nmap_status", ""),
                        "nmap_error": item.get("nmap_error", ""),
                        "nmap_hostname": item.get("nmap_hostname", ""),
                        "nmap_os": item.get("nmap_os", ""),
                        "nmap_tech_stack": item.get("nmap_tech_stack", []),
                        "verified_live": verified,
                        "domain_count": len(domains),
                    }
                }
                nodes_by_id[ip_node_id] = ip_node
                nodes.append(ip_node)

            for d in domains:
                d_raw = d.strip().lower()
                d_decoded = decode_punycode(d_raw)

                
                if d_decoded.startswith("www."):
                    d_decoded = d_decoded[4:]

                apex = cls.extract_apex_domain(d_decoded)
                is_subdomain = d_decoded != apex

                # Apex Domain Node
                apex_node_id = f"domain:{apex}"
                if apex_node_id not in nodes_by_id:
                    apex_display = format_domain_display(apex)
                    apex_node = {
                        "id": apex_node_id,
                        "label": apex,
                        "group": "apex_domain",
                        "shape": "dot",
                        "color": "#10b981", # Emerald Green
                        "title": f"<b>Apex Domain:</b> {apex_display}",
                        "details": {"domain": apex, "raw_domain": d_raw, "type": "apex", "connected_ips": set()}
                    }
                    nodes_by_id[apex_node_id] = apex_node
                    nodes.append(apex_node)

                target_domain_id = apex_node_id

                # Subdomain Node if applicable
                if is_subdomain:
                    sub_node_id = f"subdomain:{d_decoded}"
                    target_domain_id = sub_node_id
                    if sub_node_id not in nodes_by_id:
                        sub_display = format_domain_display(d_raw)
                        sub_node = {
                            "id": sub_node_id,
                            "label": d_decoded,
                            "group": "subdomain",
                            "shape": "ellipse",
                            "color": "#8b5cf6", # Purple Accent
                            "title": f"<b>Subdomain:</b> {sub_display}<br><b>Parent:</b> {apex}",
                            "details": {"domain": d_decoded, "raw_domain": d_raw, "parent": apex, "type": "subdomain", "connected_ips": set()}
                        }
                        nodes_by_id[sub_node_id] = sub_node
                        nodes.append(sub_node)

                    # Edge: Apex Domain -> Subdomain
                    edge_tuple = (apex_node_id, sub_node_id, "parent_of")
                    if edge_tuple not in seen_edges:
                        seen_edges.add(edge_tuple)
                        edges.append({
                            "from": apex_node_id,
                            "to": sub_node_id,
                            "label": "subdomain",
                            "arrows": "to",
                            "dashes": True,
                            "color": {"color": "#6b7280"},
                        })

                # Register IP to target domain node & its apex domain node
                target_node = nodes_by_id[target_domain_id]
                target_node["details"]["connected_ips"].add(ip)

                apex_node = nodes_by_id[apex_node_id]
                apex_node["details"]["connected_ips"].add(ip)

                # Edge: IP -> Domain/Subdomain
                edge_tuple_ip = (ip_node_id, target_domain_id, "hosts")
                if edge_tuple_ip not in seen_edges:
                    seen_edges.add(edge_tuple_ip)
                    edges.append({
                        "from": ip_node_id,
                        "to": target_domain_id,
                        "label": "hosts",
                        "arrows": "to",
                        "color": {"color": "#3b82f6"}, # Blue Link
                    })

        # Convert connected_ips sets to lists for JSON serialization
        for n in nodes:
            if "connected_ips" in n.get("details", {}):
                n["details"]["connected_ips"] = sorted(list(n["details"]["connected_ips"]))

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "ip_count": len([n for n in nodes if n["group"] == "ip"]),
                "apex_count": len([n for n in nodes if n["group"] == "apex_domain"]),
                "subdomain_count": len([n for n in nodes if n["group"] == "subdomain"]),
            }
        }
