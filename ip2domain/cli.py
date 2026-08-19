import argparse
import asyncio
import logging
import os
import secrets
import sys
from typing import List

from ip2domain import __version__
from ip2domain.core.ip_parser import IPParser
from ip2domain.core.engine import LookupEngine
from ip2domain.providers import ProviderManager, AVAILABLE_PROVIDERS
from ip2domain.exporters import JSONExporter, CSVExporter, TextExporter


def configure_web_api_token(host: str):
    """Generate an API token when exposing the Web UI beyond loopback."""
    if host in ("127.0.0.1", "::1", "localhost"):
        return None

    token = os.environ.get("IP2DOMAIN_API_TOKEN")
    if token:
        return None

    token = secrets.token_urlsafe(32)
    os.environ["IP2DOMAIN_API_TOKEN"] = token
    return token


def configure_web_admin():
    """Create the first administrator, generating a password when needed."""
    from ip2domain.core.storage import DB_PATH
    from ip2domain.web.auth import AuthManager

    manager = AuthManager(DB_PATH)
    if manager.count_users():
        return None

    username = os.environ.get("IP2DOMAIN_ADMIN_USERNAME", "admin")
    password = os.environ.get("IP2DOMAIN_ADMIN_PASSWORD")
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(18)
    manager.ensure_admin(username, password)
    return username, password, generated


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ip2domain",
        description="Scalable Python tool for reverse IP domain lookups supporting single IPs, CIDR blocks, and IP ranges.",
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-t",
        "--target",
        type=str,
        help="Target IP address, CIDR subnet (e.g. 1.1.1.0/24), or IP range (e.g. 192.168.1.1-192.168.1.10).",
    )
    group.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to a text file containing targets (one per line).",
    )

    parser.add_argument(
        "-p",
        "--providers",
        type=str,
        default="all",
        help=f"Comma-separated list of providers to use (Available: {','.join(AVAILABLE_PROVIDERS.keys())}, default: all).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to write the results to a file.",
    )
    parser.add_argument(
        "-fmt",
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent network requests (default: 10).",
    )
    parser.add_argument(
        "--verify",
        "--live",
        dest="verify",
        action="store_true",
        default=True,
        help="Verify that domains currently point to the target IP (enabled by default).",
    )
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                        help="Keep passive candidates without live DNS verification.")
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Perform Nmap port scanning on target IPs.",
    )
    parser.add_argument(
        "--nmap-ports",
        type=str,
        help="Custom ports for Nmap scan (e.g. 80,443,22 or 1-1000).",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch Web UI dashboard server.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to run Web UI dashboard on (default: 5000).",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host interface for Web UI server (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List available providers and exit.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debugging logs.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_providers:
        print("Available Reverse IP Providers:")
        for name, cls in AVAILABLE_PROVIDERS.items():
            print(f"  - {name:<15} : {cls.description}")
        sys.exit(0)

    if args.web:
        generated_token = configure_web_api_token(args.host)
        try:
            admin_credentials = configure_web_admin()
        except ValueError as exc:
            parser.error(str(exc))
        import uvicorn
        from ip2domain.web.app import app
        print(f"[*] Starting ip2domain Web UI server on http://{args.host}:{args.port}")
        print(f"[*] Access the Web UI in your browser at: http://localhost:{args.port} (or http://SERVER_IP:{args.port})")
        if generated_token:
            print(f"[*] Generated API token: {generated_token}")
            print("[*] Enter this token when the Web UI asks for it.")
        if admin_credentials:
            username, password, generated = admin_credentials
            print(f"[*] Created Web UI administrator: {username}")
            if generated:
                print(f"[*] Generated administrator password: {password}")
                print("[*] Save this password: it will not be shown again.")
        uvicorn.run("ip2domain.web.app:app", host=args.host, port=args.port)
        sys.exit(0)

    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    from ip2domain.core.domain_recon import DomainReconEngine

    # Check if target is a Domain Name (e.g. grinronn.ru, example.com)
    if args.target and DomainReconEngine.is_domain_target(args.target):
        print(f"[*] Target recognized as DOMAIN: {args.target}")
        print("[*] Running Domain Reconnaissance (crt.sh, HackerTarget, DNS resolution)...")

        recon_engine = DomainReconEngine(concurrency=args.concurrency)
        results = asyncio.run(recon_engine.run_domain_recon(args.target))
        ips = [r["ip"] for r in results]
        print(f"[*] Discovered {len(results)} IP(s) for domain and its subdomains.")
    else:
        # Parse target IPs
        try:
            if args.file:
                ips = list(IPParser.parse_file(args.file))
            else:
                ips = list(IPParser.parse_target(args.target))
        except Exception as e:
            print(f"Error parsing targets: {e}", file=sys.stderr)
            sys.exit(1)

        if not ips:
            print("No valid IP addresses parsed from targets.", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Parsed {len(ips)} IP address(es) to process.")

        # Setup providers
        provider_list = [p.strip() for p in args.providers.split(",")] if args.providers else ["all"]
        provider_manager = ProviderManager(selected_providers=provider_list)

        # Setup engine & execute
        engine = LookupEngine(
            provider_manager=provider_manager,
            concurrency=args.concurrency,
            verify_live=args.verify,
        )
        if args.verify:
            print("[*] Live verification ENABLED: Filtering for domains that currently resolve to the target IP...")
        print(f"[*] Running lookups across providers using concurrency limit of {args.concurrency}...")

        results = asyncio.run(engine.run(ips))

    # Optional Nmap execution
    if args.nmap:
        from ip2domain.modules.nmap_scanner import NmapScanner
        scanner = NmapScanner(ports=args.nmap_ports)
        if scanner.is_available():
            print("[*] Running Nmap port scan on target IPs...")
            port_map = asyncio.run(scanner.scan_ips_concurrently(ips, max_concurrency=args.concurrency))
            for item in results:
                ip = item["ip"]
                item["open_ports"] = port_map.get(ip, [])
        else:
            print("[!] Nmap executable not found on system. Skipping port scan.", file=sys.stderr)

    # 4. Format & Export
    if args.format == "json":
        exporter = JSONExporter()
    elif args.format == "csv":
        exporter = CSVExporter()
    else:
        exporter = TextExporter()

    output_str = exporter.export(results, output_file=args.output)
    print("\n" + output_str)

    if args.output:
        print(f"\n[*] Results successfully saved to: {args.output}")


if __name__ == "__main__":
    main()
