"""Standalone inventory CLI; deliberately separate from the legacy CLI."""
import argparse
import asyncio
import json

from .capabilities import capabilities
from .persistence import InventoryRepository
from .pipeline import run_scan
from .policies import COMMON_TCP, PROFILES, ScanConfig


def main():
    parser = argparse.ArgumentParser(description="Scanner v2 authorized service inventory")
    parser.add_argument("--db", default="scanner_v2.db")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities")
    scan = sub.add_parser("scan")
    scan.add_argument("targets", help="Numeric IP/CIDR/ranges; comma or newline separated")
    scan.add_argument("--exclude", default="")
    scan.add_argument("--profile", choices=PROFILES, default="inventory_safe")
    scan.add_argument("--tcp-ports", default=COMMON_TCP)
    scan.add_argument("--udp-ports", default="")
    scan.add_argument("--workers", type=int, default=8)
    scan.add_argument("--discovery-workers", type=int, default=4)
    scan.add_argument("--enrichment-workers", type=int, default=2)
    scan.add_argument("--queue-capacity", type=int, default=1024)
    scan.add_argument("--rate", type=float, default=20)
    scan.add_argument("--network-id", default="local")
    scan.add_argument("--active-consent", action="store_true")
    scan.add_argument("--authorized", action="store_true", help="Confirm authorization for the scope")
    scan.add_argument("--nmap", action="store_true")
    scan.add_argument("--probes", default=None, help="Comma-separated native probe IDs; empty disables active probes")
    scan.add_argument("--retain-all-states", action="store_true")
    scan.add_argument("--industrial-consent", action="store_true")
    scan.add_argument("--modbus-unit-id", type=int, default=1)
    scan.add_argument("--web-enrichment", action="store_true")
    scan.add_argument("--resource-path", action="append", help="Origin-relative path; repeat up to eight times")
    resume = sub.add_parser("resume")
    resume.add_argument("id")
    resume.add_argument("--authorized", action="store_true")
    status = sub.add_parser("status")
    status.add_argument("id")
    export = sub.add_parser("export")
    export.add_argument("id")
    args = parser.parse_args()
    if args.command == "capabilities":
        print(json.dumps(capabilities(), indent=2))
        return
    repository = InventoryRepository(args.db)
    if args.command in ("scan", "resume") and not args.authorized:
        parser.error("--authorized is required")
    if args.command == "scan":
        try:
            config = ScanConfig(
                targets=args.targets, exclusions=args.exclude, profile=args.profile,
                tcp_ports=args.tcp_ports, udp_ports=args.udp_ports, workers=args.workers,
                discovery_workers=args.discovery_workers, enrichment_workers=args.enrichment_workers,
                queue_capacity=args.queue_capacity,
                rate=args.rate, network_id=args.network_id, active_consent=args.active_consent, nmap=args.nmap,
                enabled_probes=None if args.probes is None else tuple(filter(None, args.probes.split(","))),
                retain_all_states=args.retain_all_states,
                industrial_consent=args.industrial_consent, modbus_unit_id=args.modbus_unit_id,
                web_enrichment=args.web_enrichment, resource_paths=tuple(args.resource_path or ["/"]),
            )
            identifier = repository.create(config, config.plan(), exclusive=True)
        except ValueError as exc:
            parser.error(str(exc))
        print(identifier, flush=True)
        asyncio.run(run_scan(repository, identifier))
    elif args.command == "resume":
        if not repository.resume(args.id):
            parser.error("scan cannot be resumed")
        asyncio.run(run_scan(repository, args.id))
    elif args.command == "status":
        print(json.dumps(repository.get(args.id), indent=2))
    else:
        offset = 0
        while True:
            rows = repository.endpoints(args.id, limit=500, offset=offset)
            if not rows:
                break
            for row in rows:
                print(json.dumps(row))
            offset += len(rows)


if __name__ == "__main__":
    main()
