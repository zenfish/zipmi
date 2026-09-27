#!/usr/bin/env python3
# z-artifact: 8b2cb513-3e15-44c4-b6e0-745c006119d2
"""Generate current iDRAC9 operation reference and firmware dispatch table."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path

from oem_command_table import render_command_table
from oem_reference import render_reference

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "zipmi/data/sources/idrac9-commands.json"
DISPATCH_SOURCE = ROOT / "zipmi/data/sources/idrac9-dispatch-tables.md"
REFERENCE = ROOT / "docs/idrac9-command-reference.html"
TABLE = ROOT / "docs/idrac9-command-table.html"
REFERENCE_ARTIFACT = "99f51650-f4a9-460d-90b9-58f7c4131e8a generated"
TABLE_ARTIFACT = "a897957a-00f7-4aff-953b-87f237c9544b generated"
PRIVILEGE = {0: "Unspecified", 1: "Callback", 2: "User", 3: "Operator", 4: "Administrator", 5: "OEM"}

DESTRUCTIVE = (
    "factoryreset", "factory reset", "lclwipe", "systemerase", "deletepartition",
    "deletedynamicpartition", "formatpartition", "secureupdatepartition",
    "beginsecupd", "startsecupd", "processsecupd", "endsecupd", "compliantupdupdate",
)
DISRUPTIVE = (
    "bladeacpowercycle", "specialaccycle", "disconnectnetworkiso", "detachpartition",
    "hideexecs", "chassis control",
)
SENSITIVE = (
    "password", "credential", "certificate", "securitykey", "security key",
    "authentication", "setuser", "set user", "activatesession", "sessionpriv",
    "raw peci", "i2c", "encryption", "secret", "secure boot", "signcertificate",
)
STATE_VERBS = (
    "set", "write", "add", "clear", "delete", "create", "attach", "enable",
    "disable", "control", "post", "activate", "deactivate", "update", "manage",
    "acknowledge", "collectdata", "beginmarker", "endmarker", "updatemarker",
)
READ_MARKERS = ("get", "read", "query", "status", "info", "capabil", "list", "check")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_data():
    sys.path.insert(0, str(ROOT))
    from zipmi.cli.oem_cmds import _vendor_listing
    from zipmi.scapy_ipmi.oem.idrac9 import IDRAC9_COMMANDS
    from zipmi.scapy_ipmi.oem.idrac9_binary_names import IDRAC9_BINARY_NAMES
    from zipmi.scapy_ipmi.oem.idrac9_dispatch_generated import IDRAC9_DISPATCH_ENTRIES

    return IDRAC9_COMMANDS, IDRAC9_DISPATCH_ENTRIES, IDRAC9_BINARY_NAMES, _vendor_listing("idrac9")


def safety(row: dict) -> str:
    name = row["name"].lower().replace("_", "")
    purpose = row["purpose"].lower()
    security = row["security"].lower()
    semantics = f"{name} {purpose}"
    if any(term in semantics for term in DESTRUCTIVE):
        return "destructive"
    if any(term in semantics for term in DISRUPTIVE):
        return "disruptive"
    if any(term in f"{semantics} {security}" for term in SENSITIVE):
        return "sensitive"
    leaf = name.rsplit("/", 1)[-1]
    if leaf.startswith("0x") or leaf == "default":
        leaf = name.split("/", 1)[0]
    if any(term in leaf for term in STATE_VERBS) or purpose.startswith(("write ", "set ", "spawn ", "initiate ", "trigger ")):
        return "state-changing"
    if any(term in leaf for term in READ_MARKERS) or purpose.startswith(("return ", "read ", "query ", "retrieve ", "report ")):
        return "read-only"
    return "unknown"


def subcommand_bytes(value: int | None) -> bytes:
    if value is None:
        return b""
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def operation_id(command) -> str:
    base = f"{command.netfn:02x}/{command.cmd:02x}"
    prefix = subcommand_bytes(command.subcmd)
    return base if not prefix else base + " data " + " ".join(f"{byte:02x}" for byte in prefix)


def completion_codes(row: dict) -> str:
    codes = []
    for text in (row["purpose"], row["request"], row["response"]):
        for code in re.findall(r"(?i)\bCC(?:=|\s+)(0x[0-9a-f]{2})", text):
            code = code.lower()
            if code not in codes:
                codes.append(code)
    return ", ".join(codes) or "See response summary; not separately normalized"


def live_text(live: dict) -> str:
    cc = live.get("cc")
    cc_text = f"0x{cc:02x}" if isinstance(cc, int) else "not parsed"
    return (f'{live.get("verdict", "observed")}; host {live.get("host", "unspecified")}; '
            f'CC {cc_text}; data {live.get("resp") or "(empty)"}')


def operation(command, row: dict, listing_row: dict) -> dict:
    request_status = "Unknown" if row["request"] == "undetermined" else "Partial"
    response_status = "Unknown" if row["response"] == "undetermined" else "Partial"
    live = row["live"]
    evidence = f'Library: {row["lib"]}; backend dependencies: {row["backendDeps"]}'
    if row["security"]:
        evidence += f'; security analysis: {row["security"]}'
    return {
        "id": operation_id(command),
        "send": (f'zipmi oem idrac9 --unsafe {shlex.quote(listing_row["name"])} '
                 "<remaining payload bytes>"),
        "name": row["name"],
        "purpose": row["purpose"],
        "safety": safety(row),
        "safety_note": ("Conservative classification from recovered behavior; exact payload codec is not proven."
                        if safety(row) != "unknown" else "External effect is not established."),
        "execution": "Requires --unsafe",
        "request": {
            "status": request_status, "length": "Unknown",
            "summary": row["request"], "fields": None,
        },
        "response": {
            "status": response_status, "length": "Unknown",
            "summary": row["response"], "fields": None,
        },
        "privilege": row["priv"],
        "interface": ("System interface only (KCS/in-band)" if row["inBandOnly"]
                      else "Out-of-band or system interface, subject to operation gates"),
        "availability": ("Cataloged statically; live target reported the operation absent"
                         if live["verdict"] == "ABSENT" else "Observed by the live firmware sweep"),
        "completion_codes": completion_codes(row),
        "live": True,
        "live_text": live_text(live),
        "evidence": evidence,
        "confidence": row["confidence"],
    }


def reference_page() -> dict:
    commands, registrations, _binary_names, listing = runtime_data()
    source = json.loads(SOURCE.read_text())
    rows = source["commands"]
    if not (len(commands) == len(rows) == 276):
        raise SystemExit("expected 276 iDRAC9 operation contracts")
    operations = []
    for command, row in zip(commands, rows):
        if (command.name, command.netfn, command.cmd) != (
            row["name"], int(row["netfn"], 0), int(row["cmd"], 0),
        ):
            raise SystemExit(f'catalog/runtime mismatch at {row["name"]}')
        key = (command.netfn, command.cmd, *subcommand_bytes(command.subcmd))
        operations.append(operation(command, row, listing[key]))
    pairs = sorted({(command.netfn, command.cmd) for command in commands})
    if len(pairs) != 58 or len(registrations) != 293:
        raise SystemExit("unexpected iDRAC9 operation or dispatch denominator")
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "Dell iDRAC9 OEM IPMI command reference",
        "scope": ("Firmware-bound operation reference for 276 recovered contracts over 58 "
                  "NetFn/Cmd addresses in iDRAC9 firmware 7.20.30.50."),
        "provenance": [
            ("Controller", "Dell iDRAC9"),
            ("Firmware", "7.20.30.50; extracted image firmimgFIT.d9"),
            ("Operation catalog SHA-256", f"<code>{digest(SOURCE)}</code>"),
            ("Dispatch extraction SHA-256", f"<code>{digest(DISPATCH_SOURCE)}</code>"),
            ("Denominators", "276 operation contracts / 58 addresses; 293 firmware registrations / 271 dispatch identities"),
        ],
        "links": [{
            "label": "zBMC iDRAC9 firmware analysis",
            "href": "https://github.com/zenfish/zbmc/tree/main/boxes/idrac9",
        }],
        "operations": operations,
        "commands": [{"netfn": netfn, "cmd": cmd} for netfn, cmd in pairs],
        "gaps": ("The 276 operation contracts cover 58 multiplexed addresses; they are not the "
                 "full dispatch denominator. The companion compact table retains all 293 firmware "
                 "registrations and 271 unique NetFn/Cmd identities. Exactly 43 contracts retain "
                 "undetermined request and response layouts. No iDRAC9 operation has a proven exact "
                 "payload codec or length bound in zipmi, so every named route requires --unsafe."),
        "live_evidence": ("All 276 contracts retain the structured sweep result from 10.0.9.9: "
                          "267 were confirmed as real dispatch paths and nine returned ABSENT. A live "
                          "response proves only the recorded request; it is not permission to replay "
                          "state-changing or destructive commands."),
        "sources": [
            '<a href="../zipmi/data/sources/idrac9-commands.json">Rich operation catalog and live sweep</a>',
            '<a href="idrac9-command-table.html">Corrected compact firmware dispatch table</a>',
        ],
    }


def compact_table_page() -> dict:
    _commands, registrations, binary_names, _listing = runtime_data()
    rows = []
    table_indexes: dict[str, int] = {}
    runtime_bound = runtime_resolved = 0
    for entry in registrations:
        index = table_indexes.get(entry.table, 0)
        table_indexes[entry.table] = index + 1
        handler = entry.handler_symbol
        resolution = "direct handler pointer"
        if handler == "(runtime-bound)":
            runtime_bound += 1
            resolved = binary_names.get((entry.netfn, entry.cmd))
            if resolved:
                handler = resolved[0]
                resolution = f"runtime-bound; resolved by address map in {resolved[1]}"
                runtime_resolved += 1
            else:
                resolution = "runtime-bound; handler symbol unresolved"
        rows.append({
            "address": f"0x{entry.netfn:02x} / 0x{entry.cmd:02x}",
            "qualifier": "—",
            "handler": handler,
            "privilege": PRIVILEGE.get(entry.priv, f"Firmware value 0x{entry.priv:02x}"),
            "request": "Not encoded in the 8-byte dispatch record",
            "activation": f"Static registration; {resolution}",
            "evidence": (f"{entry.table} row {index}; flags 0x{entry.flags:02x}; "
                         f"handler address 0x{entry.handler_addr:08x}"),
        })
    identities = {(entry.netfn, entry.cmd) for entry in registrations}
    if len(rows) != 293 or len(identities) != 271 or runtime_bound != 239 or runtime_resolved != 166:
        raise SystemExit("unexpected iDRAC9 dispatch-table denominator")
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "Dell iDRAC9 compact firmware command table",
        "scope": ("Current static dispatch extraction for iDRAC9 firmware 7.20.30.50. "
                  "Duplicate address registrations remain separate."),
        "provenance": [
            ("Target", "Dell iDRAC9 firmware 7.20.30.50 / firmimgFIT.d9"),
            ("Canonical dispatch SHA-256", f"<code>{digest(DISPATCH_SOURCE)}</code>"),
            ("Denominator", "293 registrations across 271 unique NetFn/Cmd identities"),
        ],
        "metrics": [
            (293, "Registration rows"), (271, "Unique NetFn/Cmd identities"),
            (239, "Runtime-bound registrations"), (73, "Runtime-bound symbols unresolved"),
        ],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/idrac9-dispatch-tables.md",
             "label": "Current firmware dispatch extraction"},
            {"href": "idrac9-command-reference.html",
             "label": "Operation-level command reference"},
        ],
    }


def emit(path: Path, text: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == text
    path.write_text(text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    valid = emit(REFERENCE, render_reference(reference_page()), args.check)
    valid &= emit(TABLE, render_command_table(compact_table_page()), args.check)
    if args.check and not valid:
        print("iDRAC9 generated documentation is stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
