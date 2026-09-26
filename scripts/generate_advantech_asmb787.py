#!/usr/bin/env python3
"""Import and generate the Advantech ASMB-787 OEM command catalog."""

from __future__ import annotations

import argparse
import csv
import html
import io
import pprint
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-oem-dispatch.csv"
ACTIVATION_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-module-activation.csv"
MODULE = ROOT / "zipmi/scapy_ipmi/oem/advantech_asmb787_generated.py"
DOC = ROOT / "docs/advantech_ASMB787-command-reference.html"
DOC_MD = ROOT / "docs/advantech_ASMB787-command-reference.md"
BASE_FIELDS = (
    "netfn", "cmd", "selector", "selector_status", "handler", "module",
    "table", "category", "table_address", "entry_address", "privilege_raw",
    "privilege", "request_length_raw", "request_length_semantics",
    "interface_raw", "interface_semantics", "netfn_evidence", "entry_evidence",
    "module_sha256", "confidence", "activation_status",
)
SEMANTIC_FIELDS = (
    "request_semantics",
    "response_semantics",
    "semantic_source",
    "semantic_confidence",
    "safety_tier",
)


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        fields = tuple(reader.fieldnames or ())
        if fields not in (BASE_FIELDS, BASE_FIELDS + SEMANTIC_FIELDS):
            raise SystemExit(f"unexpected CSV schema: {fields!r}")
        rows = list(reader)
    keys = [(int(r["netfn"], 0), int(r["cmd"], 0)) for r in rows]
    if len(rows) != 187 or len(set(keys)) != 187:
        raise SystemExit(f"expected 187 unique NetFn/Cmd rows, got {len(rows)}/{len(set(keys))}")
    privilege = {
        0x02: "User", 0x03: "Operator", 0x04: "Administrator",
        0x81: "special/raw 0x81", 0x82: "special/raw 0x82",
    }
    interfaces = {
        0x0000: "default/unrestricted branch",
        0x0008: "interface selector 0x0008 (default-supported branch)",
        0x00FF: "interface selector 0x00ff (default-supported branch)",
        0xFFFF: "default/unrestricted branch",
    }
    for row in rows:
        netfn, cmd = int(row["netfn"], 0), int(row["cmd"], 0)
        priv, req_len, interface = (int(row[name], 0) for name in
                                    ("privilege_raw", "request_length_raw", "interface_raw"))
        if not (0 <= netfn <= 0x3F and 0 <= cmd <= 0xFF and
                0 <= priv <= 0xFF and 0 <= req_len <= 0xFF and 0 <= interface <= 0xFFFF):
            raise SystemExit(f"out-of-range field in {row['netfn']}/{row['cmd']}")
        if row["category"] not in {"core", "platform", "plugin"}:
            raise SystemExit(f"bad category in {row['netfn']}/{row['cmd']}")
        if privilege.get(priv) != row["privilege"]:
            raise SystemExit(f"privilege raw/decoded mismatch in {row['netfn']}/{row['cmd']}")
        if interfaces.get(interface) != row["interface_semantics"]:
            raise SystemExit(f"interface raw/decoded mismatch in {row['netfn']}/{row['cmd']}")
        expected_len = ("variable/unconstrained by dispatcher" if req_len == 0xFF
                        else f"exactly {req_len} request payload bytes")
        if row["request_length_semantics"] != expected_len:
            raise SystemExit(f"request length raw/decoded mismatch in {row['netfn']}/{row['cmd']}")
        if not re.fullmatch(r"[0-9a-f]{64}", row["module_sha256"]):
            raise SystemExit(f"bad module SHA-256 in {row['netfn']}/{row['cmd']}")
        if any(not (0 <= int(row[name], 0) <= 0xFFFFFFFF)
               for name in ("table_address", "entry_address")):
            raise SystemExit(f"out-of-range address in {row['netfn']}/{row['cmd']}")
        if row["selector"] or row["selector_status"] != (
                "no selector in first-level dispatch; handler payload selectors unknown "
                "unless separately documented"):
            raise SystemExit(f"selector fields inconsistent in {row['netfn']}/{row['cmd']}")
        if fields == BASE_FIELDS + SEMANTIC_FIELDS:
            if row["semantic_confidence"] not in {
                    "unknown",
                    "medium for AMI-family context; exact ASMB applicability unverified",
            } or row["safety_tier"] not in {"safe", "mutates", "destructive", "unknown"}:
                raise SystemExit(f"bad semantic enum in {row['netfn']}/{row['cmd']}")
        if not all(row[name] for name in ("handler", "module", "table", "confidence",
                                          "activation_status", "selector_status")):
            raise SystemExit(f"missing evidence field in {row['netfn']}/{row['cmd']}")
        activation_label(row["activation_status"])
    return rows


def enrich(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Add explicitly labelled AMI-family context without overriding ASMB facts."""
    sys.path.insert(0, str(ROOT))
    from zipmi.scapy_ipmi.oem.megarac import MEGARAC_COMMANDS
    from zipmi.scapy_ipmi.oem.yafu import YAFU_COMMANDS

    for row in rows:
        if row.get("semantic_confidence") not in (None, "", "unknown"):
            continue
        key = (int(row["netfn"], 0), int(row["cmd"], 0))
        context = YAFU_COMMANDS.get(key) or MEGARAC_COMMANDS.get(key)
        row["request_semantics"] = "unknown beyond dispatcher request-length constraint"
        row["response_semantics"] = "unknown"
        row["semantic_source"] = "ASMB-787 dispatcher registration (structure only)"
        row["semantic_confidence"] = "unknown"
        row["safety_tier"] = "unknown"
        if context:
            row["request_semantics"] = context.get("request") or row["request_semantics"]
            row["response_semantics"] = context.get("response") or row["response_semantics"]
            family = "yafu.py" if key in YAFU_COMMANDS else "megarac.py"
            row["semantic_source"] = (
                f"zipmi.scapy_ipmi.oem.{family} from AMI client/header research; "
                "ASMB handler semantics not independently proved"
            )
            row["semantic_confidence"] = (
                "medium for AMI-family context; exact ASMB applicability unverified"
            )
            row["safety_tier"] = context.get("tier") or "unknown"
    return rows


def apply_activation(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    with ACTIVATION_SOURCE.open(newline="") as stream:
        modules = {row["module"]: row for row in csv.DictReader(stream)}
    plugin_rows = [row for row in rows if row["category"] == "plugin"]
    if len(modules) != 38 or sum(int(row["rows"]) for row in modules.values()) != 95:
        raise SystemExit("expected activation evidence for 38 modules / 95 plugin rows")
    if {row["module"] for row in plugin_rows} != set(modules):
        raise SystemExit("activation module set does not match dispatch catalog")
    for module, evidence in modules.items():
        count = sum(row["module"] == module for row in plugin_rows)
        if count != int(evidence["rows"]):
            raise SystemExit(f"activation row count mismatch for {module}: {count}")
    for row in plugin_rows:
        evidence = modules[row["module"]]
        if evidence["sha256"] != row["module_sha256"]:
            raise SystemExit(f"activation SHA-256 mismatch for {row['module']}")
        if evidence["result"] == "REGISTERED":
            row["activation_status"] = (
                "runtime registered: exact feature token present; loader enable, "
                "dependencies, exported table, and table merge proved"
            )
        elif evidence["result"] == "SKIPPED":
            row["activation_status"] = (
                "not runtime registered: exact feature token absent; loader skips module"
            )
        else:
            raise SystemExit(f"unknown activation result for {row['module']}")
    return rows


def source_text(rows: list[dict[str, str]]) -> str:
    fields = [k for k in rows[0] if k not in SEMANTIC_FIELDS] + list(SEMANTIC_FIELDS)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def module_text(rows: list[dict[str, str]]) -> str:
    commands = {
        (int(r["netfn"], 0), int(r["cmd"], 0)): dict(r)
        for r in rows
    }
    return (
        '"""Generated from zipmi/data/sources/advantech-asmb787-oem-dispatch.csv.\n'
        "Run scripts/generate_advantech_asmb787.py; do not edit by hand.\n"
        '"""\n\nfrom __future__ import annotations\n\n'
        "ASMB787_COMMANDS: dict[tuple[int, int], dict[str, str]] = "
        + pprint.pformat(commands, width=100, sort_dicts=True)
        + "\n\nASMB787_CMD_NAMES = {key: row['handler'] for key, row in ASMB787_COMMANDS.items()}\n"
        + "\n__all__ = ['ASMB787_COMMANDS', 'ASMB787_CMD_NAMES']\n"
    )


def activation_label(value: str) -> str:
    if value == "statically registered in owning dispatcher table":
        return "statically registered"
    if "explicitly enabled" in value:
        return "feature enabled; runtime registration unproved"
    if "absent from extracted" in value:
        return "feature absent; runtime registration unproved"
    if value.startswith("runtime registered:"):
        return "runtime registered"
    if value.startswith("not runtime registered:"):
        return "not runtime registered"
    raise SystemExit(f"unknown activation status: {value}")


def doc_text(rows: list[dict[str, str]]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    body = []
    for row in rows:
        activation = row["activation_status"]
        status = activation_label(activation)
        body.append(
            "<tr class='border-b border-slate-800 align-top'>"
            f"<td class='p-2 font-mono'>{esc(row['netfn'])}/{esc(row['cmd'])}</td>"
            f"<th scope='row' class='p-2 text-left font-normal'><strong>{esc(row['handler'])}</strong><br><span class='text-slate-400'>{esc(row['module'])}</span></th>"
            f"<td class='p-2'>{esc(row['privilege'])} <span class='font-mono text-slate-400'>({esc(row['privilege_raw'])})</span></td>"
            f"<td class='p-2'>dispatcher +8 constraint: {esc(row['request_length_semantics'])}<br><span class='text-slate-400'>{esc(row['request_semantics'])}</span></td>"
            f"<td class='p-2'>{esc(row['response_semantics'])}</td>"
            f"<td class='p-2'>{esc(row['interface_semantics'])} <span class='font-mono text-slate-400'>({esc(row['interface_raw'])})</span></td>"
            f"<td class='p-2'><strong>{esc(status)}</strong><br><span class='text-slate-400'>{esc(activation)}</span></td>"
            f"<td class='p-2'>{esc(row['confidence'])}<br><span class='text-slate-400'>{esc(row['semantic_source'])}; {esc(row['semantic_confidence'])}</span></td>"
            "</tr>"
        )
    registered = sum(row["activation_status"].startswith("runtime registered:") for row in rows)
    skipped = sum(row["activation_status"].startswith("not runtime registered:") for row in rows)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Advantech ASMB-787 OEM IPMI command reference</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-950 text-slate-100"><main class="mx-auto max-w-[110rem] p-6">
<h1 class="text-3xl font-bold">Advantech ASMB-787 OEM IPMI command reference</h1>
<p class="mt-3 text-slate-300">Complete 187-entry firmware dispatch catalog and zipmi named raw surface for unique vendor NetFn/Cmd pairs. Evidence separates 92 statically registered core/platform rows, {registered} runtime-registered plugin rows, and {skipped} plugin rows skipped because their exact feature token is absent. The CmdHndlr_T layout is <code>cmd@+0</code>, <code>privilege@+1</code>, <code>handler@+4</code>, the one-byte dispatcher request-length constraint at <code>+8</code>, and <code>interface@+12</code>. Earlier documentation swapped privilege and request length.</p>
<p class="mt-2 text-slate-300">A named command means zipmi can emit its exact NetFn/Cmd bytes. It does not claim a structured codec, complete request/response semantics, or runtime reachability. The +8 value proves only the dispatcher constraint shown; payload fields remain explicitly unknown unless AMI client/header material supplies labelled context. Type-8 secondary selector hooks exist, but their selector values remain unknown.</p>
<div class="mt-6 overflow-x-auto"><table class="w-full text-sm"><caption class="pb-3 text-left text-slate-300">All 187 unique ASMB-787 vendor NetFn/Cmd catalog entries and their evidence boundaries.</caption><thead class="sticky top-0 bg-slate-900 text-left"><tr><th scope="col" class="p-2">Wire</th><th scope="col" class="p-2">Handler / module</th><th scope="col" class="p-2">Privilege</th><th scope="col" class="p-2">Request</th><th scope="col" class="p-2">Response</th><th scope="col" class="p-2">Interface</th><th scope="col" class="p-2">Activation</th><th scope="col" class="p-2">Evidence / confidence</th></tr></thead><tbody>""" + "".join(body) + """</tbody></table></div>
<p class="mt-6 text-slate-400">Generated from <code>zipmi/data/sources/advantech-asmb787-oem-dispatch.csv</code> by <code>scripts/generate_advantech_asmb787.py</code>.</p>
</main></body></html>
"""


def markdown_text(rows: list[dict[str, str]]) -> str:
    def cell(value: str) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        "# Advantech ASMB-787 OEM IPMI command reference",
        "",
        "> Generated from "
        "[`zipmi/data/sources/advantech-asmb787-oem-dispatch.csv`](../zipmi/data/sources/advantech-asmb787-oem-dispatch.csv) "
        "by `scripts/generate_advantech_asmb787.py`; do not edit by hand. "
        "The [HTML reference](advantech_ASMB787-command-reference.html) is the styled view of the same rows.",
        "",
        "This is the complete 187-entry firmware dispatch catalog and zipmi named raw surface for unique vendor NetFn/Cmd pairs: 92 statically registered core/platform rows, 85 feature-enabled plugin declarations whose runtime registration was not directly proved, and 10 feature-absent plugin declarations. A named command proves exact NetFn/Cmd bytes, not a structured codec, complete request/response semantics, or runtime reachability. The one-byte field at `CmdHndlr_T +8` supplies only the dispatcher request-length constraint.",
        "",
        "| Wire | Handler / module | Privilege | Request | Response | Interface | Activation | Evidence / confidence | Safety |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        values = (
            f"`{row['netfn']}/{row['cmd']}`",
            f"`{row['handler']}`<br>{row['module']}",
            f"{row['privilege']} (`{row['privilege_raw']}`)",
            f"dispatcher +8: {row['request_length_semantics']}<br>{row['request_semantics']}",
            row["response_semantics"],
            f"{row['interface_semantics']} (`{row['interface_raw']}`)",
            f"{activation_label(row['activation_status'])}<br>{row['activation_status']}",
            f"{row['confidence']}<br>{row['semantic_source']}; {row['semantic_confidence']}",
            row["safety_tier"],
        )
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    return "\n".join(lines) + "\n"


def emit(path: Path, text: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == text
    path.write_text(text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--import-csv", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.import_csv:
        if args.check:
            parser.error("--check and --import-csv are mutually exclusive")
        rows = enrich(read_rows(args.import_csv))
    else:
        rows = read_rows(SOURCE)
    rows = apply_activation(rows)
    ok = emit(SOURCE, source_text(rows), args.check)
    ok &= emit(MODULE, module_text(rows), args.check)
    ok &= emit(DOC, doc_text(rows), args.check)
    ok &= emit(DOC_MD, markdown_text(rows), args.check)
    if args.check and not ok:
        print("ASMB-787 generated files are stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
