#!/usr/bin/env python3
# z-artifact: 7ce02d9b-e895-49b8-aa43-93bc2fd14c32
"""Generate the firmware-bound zero-OEM vanilla OpenBMC documentation pair."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from oem_command_table import render_command_table
from oem_reference import render_reference


SOURCE = ROOT / "zipmi/data/sources/openbmc-vanilla-oem-closure.json"
REFERENCE = ROOT / "docs/openbmc-vanilla-command-reference.html"
TABLE = ROOT / "docs/openbmc-vanilla-command-table.html"
REFERENCE_ARTIFACT = "96279623-aa74-4fa3-b3e5-a7034b6944c8 generated"
TABLE_ARTIFACT = "2903af35-c64a-4f26-a947-e1484ff8612a generated"
UPSTREAM_RECIPE = (
    "https://github.com/openbmc/openbmc/blob/"
    "5d179dab3c66c8b89e059eeb17b038a2beb435d3/"
    "meta-phosphor/recipes-phosphor/ipmi/phosphor-ipmi-host_git.bb"
)


def closure() -> dict:
    return json.loads(SOURCE.read_text())


def reference_page(data: dict) -> dict:
    image = data["image"]
    build = data["build"]
    census = data["registration_census"]
    live = data["live_evidence"]
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "Vanilla AST2600 OpenBMC OEM IPMI command reference",
        "scope": (
            "Firmware-bound proof that the pinned upstream evb-ast2600 image registers "
            "no vendor OEM IPMI commands. Standard IPMI and DCMI remain supported by zipmi."
        ),
        "provenance": [
            ("Target", "Vanilla upstream OpenBMC; <code>evb-ast2600</code>"),
            ("OpenBMC build", f'<code>{build["version"]}</code>; build <code>{build["build_id"]}</code>'),
            ("Source commit", f'<code>{build["openbmc_commit"]}</code>'),
            ("Firmware SHA-256", f'<code>{image["sha256"]}</code>'),
            ("Firmware size", f'{image["size"]:,} bytes'),
            ("Provider census", f'{len(data["providers"])} payloads; no vendor OEM provider'),
            ("Static census", f'{census["total_call_sites"]} standard/DCMI registration call sites; 0 OEM call sites'),
            ("Live closure", f'{live["completion_code_c1"]:,} OEM probes returned CC c1; 0 errors'),
        ],
        "links": [{"label": "Compact vanilla OpenBMC command table", "href": "openbmc-vanilla-command-table.html"}],
        "operations": [],
        "commands": [],
        "gaps": (
            "No OEM inventory gap remains for this exact image. Its 81 handler-registration call "
            "sites are confined to standard NetFns 0x00, 0x04, 0x06, 0x0a, and 0x0c plus DCMI "
            "group 0xdc. The separate zipmi openbmc command is an index of vendor-added provider "
            "flavors and must not be applied to this baseline image."
        ),
        "live_evidence": (
            f'Run {live["zbmc_run_id"]} reached READY and returned manufacturer/product 0/0. '
            f'All {live["direct_probes"]:,} direct OEM-NetFn probes and '
            f'{live["iana_group_probes"]:,} NetFn 0x2e probes across eleven IANA prefixes returned '
            "Invalid Command (CC c1), with no alternate completion codes or transport errors."
        ),
        "sources": [
            '<a href="../zipmi/data/sources/openbmc-vanilla-oem-closure.json">Machine-readable closure evidence</a>',
            f'<a href="{UPSTREAM_RECIPE}">Pinned upstream phosphor-ipmi-host recipe</a>',
            '<a href="https://github.com/zenfish/zbmc/blob/main/firmware/download-fw.sh">zBMC firmware hash pin</a>',
            '<a href="../zipmi/scapy_ipmi/oem/openbmc.py">zipmi OpenBMC vendor-flavor index</a>',
        ],
    }


def compact_page(data: dict) -> dict:
    image = data["image"]
    census = data["registration_census"]
    live = data["live_evidence"]
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "Vanilla AST2600 OpenBMC compact OEM command table",
        "scope": "Zero rows is the verified result: the pinned image contains no vendor OEM IPMI registrations.",
        "provenance": [
            ("Firmware SHA-256", f'<code>{image["sha256"]}</code>'),
            ("OpenBMC source", f'<code>{data["build"]["openbmc_commit"]}</code>'),
            ("Provider payloads", f'{len(data["providers"])} core providers; no vendor OEM provider'),
            ("Live sweep", f'{live["completion_code_c1"]:,} / {live["completion_code_c1"]:,} probes returned CC c1'),
        ],
        "metrics": [
            (0, "OEM registration rows"),
            (0, "Unique OEM NetFn/Cmd identities"),
            (census["total_call_sites"], "Static standard/DCMI registration call sites excluded"),
            (live["completion_code_c1"], "Negative OEM probes with CC c1"),
        ],
        "rows": [],
        "sources": [
            {"href": "../zipmi/data/sources/openbmc-vanilla-oem-closure.json", "label": "Machine-readable closure evidence"},
            {"href": "openbmc-vanilla-command-reference.html", "label": "Detailed zero-OEM reference"},
        ],
    }


def emit(path: Path, document: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == document
    path.write_text(document)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = closure()
    documents = (
        (REFERENCE, render_reference(reference_page(data))),
        (TABLE, render_command_table(compact_page(data))),
    )
    valid = all(emit(path, document, args.check) for path, document in documents)
    if args.check and not valid:
        print("Vanilla OpenBMC generated documentation is stale", file=sys.stderr)
        return 1
    if not args.check:
        for path, _document in documents:
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
