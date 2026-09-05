#!/usr/bin/env python3
"""Build and bundle camera static assets from modular source files.

Modules:
- centra/     (map, discovery, player, screens, people) -> centra.js
- strix/      (targets, scan, results, player)          -> strix.js
- scanner_v2/ (targets, scan, results, player, export)  -> scanner_v2.js
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC_CAMERAS = ROOT / "ip2domain" / "web" / "static" / "cameras"

CENTRA_ORDER = ["map.js", "discovery.js", "player.js", "screens.js", "people.js"]
STRIX_ORDER = ["targets.js", "scan.js", "results.js", "player.js"]
SCANNER_V2_ORDER = ["targets.js", "scan.js", "results.js", "player.js", "export.js"]


def bundle(source_dir: Path, target_file: Path, file_order: list[str], title: str) -> None:
    chunks = [
        f"/* {title} (Auto-bundled from {source_dir.name}/) */\n'use strict';\n"
    ]
    for filename in file_order:
        src = source_dir / filename
        if not src.exists():
            print(f"Warning: {src} does not exist")
            continue
        content = src.read_text(encoding="utf-8")
        # Remove repeated 'use strict';
        lines = [line for line in content.splitlines() if line.strip() != "'use strict';"]
        cleaned = "\n".join(lines).strip()
        chunks.append(f"\n// ════════════════════════════════════════════════════════════════\n// MODULE: {source_dir.name}/{filename}\n// ════════════════════════════════════════════════════════════════\n\n{cleaned}\n")

    target_file.write_text("\n".join(chunks), encoding="utf-8")
    print(f"✓ Bundled {len(file_order)} modules -> {target_file.relative_to(ROOT)} ({target_file.stat().st_size:,} bytes)")


def main():
    bundle(
        source_dir=STATIC_CAMERAS / "centra",
        target_file=STATIC_CAMERAS / "centra.js",
        file_order=CENTRA_ORDER,
        title="Centra Cameras Client",
    )
    bundle(
        source_dir=STATIC_CAMERAS / "strix",
        target_file=STATIC_CAMERAS / "strix.js",
        file_order=STRIX_ORDER,
        title="Strix Cameras Client",
    )
    bundle(
        source_dir=STATIC_CAMERAS / "scanner_v2",
        target_file=STATIC_CAMERAS / "scanner_v2.js",
        file_order=SCANNER_V2_ORDER,
        title="Camera Scanner v2 Client",
    )


if __name__ == "__main__":
    main()
