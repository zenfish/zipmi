#!/usr/bin/env python3
# z-artifact: 50335659-5405-40f3-8595-02faa6dca99c
"""Generate the firmware-bound Supermicro X10 reference, table, and genealogy."""

from __future__ import annotations

import argparse
import html
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.cli.oem_cmds import _vendor_listing
from zipmi.scapy_ipmi.oem.supermicro_x10 import (
    SUPERMICRO_X10,
    X10_CATALOG,
    X10_FIRMWARE_SHA256,
    X10_PROVIDER_SHA256,
    X10_REGISTRATIONS,
    X10_ROOTFS_SHA256,
)


REFERENCE = ROOT / "docs/supermicro-x10-command-reference.html"
TABLE = ROOT / "docs/supermicro-x10-command-table.html"
GENEALOGY = ROOT / "docs/supermicro-x10-x14-genealogy.html"
REFERENCE_ARTIFACT = "2a5b3b3a-119b-4208-a5ca-0012ba93a81a generated"
TABLE_ARTIFACT = "6dfa4fd2-a7f2-481e-8a2b-bada2c06c096 generated"
GENEALOGY_ARTIFACT = "2f192c7c-a550-4265-b9ae-446a482837d1 generated"


def _length(bounds: tuple[int | None, int | None]) -> str:
    low, high = bounds
    if low == high and low is not None:
        return f"Exactly {low} payload bytes"
    if high is None:
        return f"At least {low or 0} payload bytes"
    return f"{low or 0}–{high} payload bytes"


def _status(layout: dict) -> str:
    value = layout.get("status", "Partial").lower()
    return "Complete" if value.startswith("complete") else "Unknown" if value.startswith("unknown") else "Partial"


def _send(key: tuple[int, ...], row: dict) -> str:
    words = ["zipmi", "oem", "supermicro-x10"]
    if row["requires_unsafe"]:
        words.append("--unsafe")
    words.append(shlex.quote(row["name"]))
    fixed = len(row.get("prefix") or bytes(key[2:]))
    low, high = row["request_length"]
    remaining = None if low is None else max(0, low - fixed)
    if remaining or high is None or (high is not None and high > fixed):
        words.append(f"<{remaining} payload bytes>" if remaining is not None and low == high else "<payload bytes>")
    return " ".join(words)


def reference_page() -> dict:
    operations = []
    public = _vendor_listing("supermicro-x10")
    for key, row in SUPERMICRO_X10.items():
        public_row = public[key]
        display = {**row, "name": public_row["name"],
                   "requires_unsafe": public_row["requires_unsafe"]}
        source = next(item for item in X10_CATALOG["operations"] if (
            int(item["netfn"], 0), int(item["command"], 0), *item.get("prefix", ())
        ) == key)
        qualifier = " ".join(f"{byte:02x}" for byte in key[2:])
        operations.append({
            "id": f"{key[0]:02x}/{key[1]:02x}" + (f" data {qualifier}" if qualifier else ""),
            "name": display["name"], "purpose": row["purpose"], "send": _send(key, display),
            "safety": row["safety"], "safety_note": row["safety_note"],
            "execution": "Requires --unsafe" if display["requires_unsafe"] else "Allowed by default",
            "request": {"status": _status(source["request"]), "length": _length(row["request_length"]),
                        "summary": row["purpose"], "fields": row["request_fields"]},
            "response": {"status": _status(source["response"]), "length": _length(row["response_length"]),
                         "summary": row["purpose"], "fields": row["response_fields"]},
            "privilege": row["privilege"], "interface": f"Raw OEM NetFn 0x{key[0]:02x} over authenticated IPMI",
            "availability": row["activation"], "completion_codes": row["completion_codes"],
            "live": bool(row.get("live")), "live_text": row.get("live") or "No exact safe live request retained",
            "evidence": row["evidence"], "confidence": row["confidence"],
        })
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "Supermicro X10 AST2400 OEM IPMI command reference",
        "scope": "Firmware-bound contracts for every OEM registration and reachable nested operation in BMC firmware 3.93.",
        "provenance": [
            ("Target", "Supermicro X10 AST2400; BMC firmware 3.93"),
            ("Firmware SHA-256", f"<code>{X10_FIRMWARE_SHA256}</code>"),
            ("Rootfs SHA-256", f"<code>{X10_ROOTFS_SHA256}</code>"),
            ("Provider SHA-256", f"<code>{X10_PROVIDER_SHA256}</code>"),
            ("Registration closure", f"{len(X10_REGISTRATIONS)} rows / {len(X10_REGISTRATIONS)} unique wire identities"),
            ("Operation closure", f"{len(operations)} direct and nested operations"),
        ],
        "links": [
            {"label": "Compact X10 command table", "href": "supermicro-x10-command-table.html"},
            {"label": "X10 to X14 genealogy and risk", "href": "supermicro-x10-x14-genealogy.html"},
        ],
        "operations": operations,
        "commands": sorted({key[:2] for key in SUPERMICRO_X10}),
        "gaps": X10_CATALOG["closure"].get("gaps", "No unclassified registration or reachable selector remains."),
        "live_evidence": X10_CATALOG["closure"].get("live_evidence", "Safe live validation pending."),
        "sources": [
            "Pinned /lib/libipmi.so OEMCmdTable, relocation table, dispatcher disassembly, and handler decompilation.",
            "Supermicro SMCIPMITool 2.30.0 client call sites used only where the firmware route independently matches.",
        ],
    }


def table_page() -> dict:
    rows = []
    for source in X10_REGISTRATIONS:
        rows.append({
            "address": source["wire_key"], "qualifier": f"LUN {source['lun']}",
            "handler": source["handler"]["symbol"], "privilege": source["privilege"]["name"],
            "request": "Direct handler" if source["wire_key"] not in {"30/48", "30/68", "30/70", "30/74", "30/a0"}
                       else "Payload byte 0 selects a nested operation",
            "activation": "Unconditional OEMCmdTable registration",
            "evidence": (f"row {source['row_address']}; handler {source['handler']['address']}; "
                         f"relocation {source['evidence']['address']}"),
        })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "Supermicro X10 AST2400 OEM IPMI registration table",
        "scope": "One row per executed OEMCmdTable registration in the pinned BMC 3.93 provider.",
        "provenance": [
            ("Firmware SHA-256", f"<code>{X10_FIRMWARE_SHA256}</code>"),
            ("Provider SHA-256", f"<code>{X10_PROVIDER_SHA256}</code>"),
        ],
        "metrics": [
            (len(rows), "Executed registration rows"),
            (len({row["address"] for row in rows}), "Unique wire identities"),
            (len(SUPERMICRO_X10), "Documented direct and nested operations"),
        ],
        "rows": rows,
        "sources": [
            {"label": "Detailed X10 operation reference", "href": "supermicro-x10-command-reference.html"},
            {"label": "X10 to X14 genealogy and risk", "href": "supermicro-x10-x14-genealogy.html"},
        ],
    }


def genealogy_html() -> str:
    rows = X10_CATALOG["genealogy"]
    counts = {name: sum(row["relation"] == name for row in rows) for name in (
        "retained", "renamed-reframed", "behavior-changed", "x10-only-dropped", "x14-new", "repurposed", "uncertain",
    )}
    metrics = "".join(
        f'<div class="rounded-xl border border-zinc-700 bg-zinc-900 p-4"><strong class="block text-2xl">{value}</strong>{html.escape(name)}</div>'
        for name, value in counts.items()
    )
    body = "".join(
        "<tr class=\"border-t border-zinc-800\">"
        f"<td class=\"p-3 font-mono\">{html.escape(row['lineage_id'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['canonical_action'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['x10'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['x14'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['relation'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['risk_delta'])}</td>"
        f"<td class=\"p-3\">{html.escape(row['evidence'])}</td></tr>"
        for row in rows
    )
    return f'''<!doctype html>
<!-- z-artifact: {GENEALOGY_ARTIFACT} -->
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Supermicro X10 to X14 OEM IPMI genealogy and risk profile</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-zinc-950 text-zinc-100"><main class="mx-auto max-w-[1800px] p-6">
<h1 class="text-3xl font-bold">Supermicro X10 → X14 OEM IPMI genealogy and risk profile</h1>
<p class="mt-3 max-w-5xl text-zinc-300">Semantic lineage for the pinned X10 BMC 3.93 and X14 01.01.06.07 providers. Matching bytes nominate a relationship; handler behavior, privilege, persistence, and sinks decide it.</p>
<div class="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-7">{metrics}</div>
<section class="mt-8 rounded-xl border border-amber-700/60 bg-amber-950/30 p-5"><h2 class="text-xl font-semibold">Risk interpretation</h2>
<p class="mt-2 text-zinc-200">X14 removes weak cipher suites and turns several X10 shell/configuration paths into compatibility stubs, reducing legacy attack surface. It also adds distinct provisioning, D-Bus, storage, file, GPIO, and raw-memory operations. A dropped command can therefore be both a security improvement and a loss of diagnostic or recovery capability.</p></section>
<div class="mt-8 overflow-x-auto rounded-xl border border-zinc-800"><table class="min-w-full text-sm"><thead class="bg-zinc-900 text-left"><tr><th class="p-3">Lineage</th><th class="p-3">Action</th><th class="p-3">X10</th><th class="p-3">X14</th><th class="p-3">Relation</th><th class="p-3">Risk delta</th><th class="p-3">Evidence</th></tr></thead><tbody>{body}</tbody></table></div>
</main></body></html>'''


def _write(path: Path, content: str, check: bool) -> None:
    content = content.rstrip() + "\n"
    if check:
        if not path.exists() or path.read_text() != content:
            raise SystemExit(f"stale generated file: {path}")
    else:
        path.write_text(content)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    _write(REFERENCE, render_reference(reference_page()), args.check)
    _write(TABLE, render_command_table(table_page()), args.check)
    _write(GENEALOGY, genealogy_html(), args.check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
