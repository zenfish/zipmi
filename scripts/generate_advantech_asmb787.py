#!/usr/bin/env python3
"""Import and generate the Advantech ASMB-787 OEM command catalog."""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import pprint
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-oem-dispatch.csv"
ACTIVATION_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-module-activation.csv"
CONTRACTS_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-oem-contracts.json"
HEADER_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-header-contracts.csv"
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
                    "target-proven",
            } or row["safety_tier"] not in {
                    "safe", "mutates", "security-sensitive", "destructive", "unknown"}:
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


def operation_prefix(layout: str) -> list[int] | None:
    """Return only exact, leading handler-proven discriminator bytes."""
    prefix = []
    for token in (part.strip() for part in layout.split(";")):
        if re.fullmatch(r"0x[0-9a-fA-F]{2}", token):
            prefix.append(int(token, 16))
            continue
        match = re.fullmatch(
            r"(?:action|selector|operation|media_type|flags|magic|reserved)=([0-9a-fA-F]{1,2})",
            token,
        )
        if match:
            prefix.append(int(match.group(1), 16))
            continue
        match = re.fullmatch(r"db([01])", token)
        if match:
            prefix.append(int(match.group(1)))
            continue
        break
    return prefix or None


def field_descriptors(layout: str, expected_length: str) -> list[dict] | None:
    """Flatten the fixed-width subset of recovered packed wire layouts."""
    if not expected_length.isdigit() or any(marker in layout for marker in (
            "PLDM", "helper-defined", "typed_body", "entries[N]", "username;password",
            "chunk_u16le", "zero header", "remaining header", "data")):
        return None
    if layout == "empty":
        return [] if expected_length == "0" else None
    fields = []
    for index, token in enumerate(part.strip() for part in layout.split(";")):
        if token == "cc":
            fields.append({"name": "completion_code", "kind": "u8"})
            continue
        if re.fullmatch(r"0x[0-9a-fA-F]{2}", token):
            fields.append({"name": f"constant_{index}", "kind": "u8",
                           "constant": int(token, 16)})
            continue
        match = re.fullmatch(r"([A-Za-z_]\w*)=([0-9a-fA-F]{1,2})", token)
        if match:
            fields.append({"name": match.group(1), "kind": "u8",
                           "constant": int(match.group(2), 16)})
            continue
        match = re.fullmatch(r"db([01])", token)
        if match:
            fields.append({"name": "database", "kind": "u8",
                           "constant": int(match.group(1))})
            continue
        match = re.fullmatch(r"([A-Za-z_]\w*)\[(\d+)\]", token)
        if match:
            fields.append({"name": match.group(1), "kind": "bytes",
                           "length": int(match.group(2))})
            continue
        match = re.fullmatch(r"([A-Za-z_]\w*)_(u16le|u32le)", token)
        if match:
            fields.append({"name": match.group(1), "kind": match.group(2)})
            continue
        match = re.fullmatch(r"([A-Za-z_]\w*)(?:=\([^)]*\))?", token)
        if match:
            fields.append({"name": match.group(1), "kind": "u8"})
            continue
        return None
    widths = {"u8": 1, "u16le": 2, "u32le": 4}
    size = sum(field.get("length", widths.get(field["kind"], 0)) for field in fields)
    return fields if size == int(expected_length) else None


def apply_contracts(rows: list[dict[str, str]]) -> list[dict]:
    document = json.loads(CONTRACTS_SOURCE.read_text())
    operations = document.get("operations", [])
    if document.get("schema_version") != 1 or len(operations) != 462:
        raise SystemExit("expected ASMB contract schema v1 with 462 operations")
    by_key = {(int(row["netfn"], 0), int(row["cmd"], 0)): row for row in rows}
    ids = set()
    keys = set()
    for operation in operations:
        op_id = operation["id"]
        key = tuple(operation["command"])
        if op_id in ids or key not in by_key:
            raise SystemExit(f"duplicate or unknown ASMB operation: {op_id}")
        ids.add(op_id)
        row = by_key[key]
        dispatch_sha256 = operation["evidence"].get(
            "dispatch_module_sha256", operation["evidence"]["module_sha256"])
        if dispatch_sha256 != row["module_sha256"]:
            raise SystemExit(f"contract SHA-256 mismatch for {op_id}")
        prefix = operation_prefix(operation["request"]["layout"])
        operation["prefix"] = prefix
        request_fields = field_descriptors(
            operation["request"]["layout"], operation["request"]["length"])
        response_fields = field_descriptors(
            operation["response"]["layout"], operation["response"]["length_including_cc"])
        operation["request"]["fields"] = request_fields
        operation["response"]["fields"] = response_fields
        operation["codec_state"] = (
            "verified" if request_fields is not None and response_fields is not None else "raw-exact"
        )
        if prefix is not None:
            op_key = key + tuple(prefix)
            if op_key in keys:
                raise SystemExit(f"duplicate ASMB operation prefix: {op_key}")
            keys.add(op_key)
    unprefixed = {}
    for operation in operations:
        if operation["codec_state"] == "verified" and operation["prefix"] is None:
            key = tuple(operation["command"])
            unprefixed[key] = unprefixed.get(key, 0) + 1
    for operation in operations:
        key = tuple(operation["command"])
        if operation["prefix"] is None and unprefixed.get(key, 0) > 1:
            operation["codec_state"] = "raw-exact"
    if len({tuple(operation["command"]) for operation in operations}) != 187:
        raise SystemExit("expected exact contracts for 187 ASMB command pairs")
    rank = {"safe": 0, "mutates": 1, "security-sensitive": 2, "destructive": 3}
    for key, row in by_key.items():
        matching = [operation for operation in operations if tuple(operation["command"]) == key]
        if not matching:
            continue
        row["request_semantics"] = "; ".join(dict.fromkeys(
            operation["request"]["layout"] for operation in matching))
        row["response_semantics"] = "; ".join(dict.fromkeys(
            operation["response"]["layout"] for operation in matching))
        row["semantic_source"] = "exact ASMB-787 handler decompilation"
        row["semantic_confidence"] = "target-proven"
        row["safety_tier"] = max((operation["effect"] for operation in matching), key=rank.get)
    return operations


def validate_header_context(rows: list[dict[str, str]]) -> None:
    with HEADER_SOURCE.open(newline="") as stream:
        headers = list(csv.DictReader(stream))
    row_keys = [(row["netfn"], row["cmd"], row["handler"]) for row in rows]
    header_keys = [(row["netfn"], row["cmd"], row["handler"]) for row in headers]
    if header_keys != row_keys:
        raise SystemExit("ASMB sibling-header map does not match dispatch ordering/identity")
    coverage = {"full": 0, "partial": 0, "none": 0}
    for row in headers:
        if not row["unresolved"]:
            coverage["full"] += 1
        elif not row["request_type"] and not row["response_type"]:
            coverage["none"] += 1
        else:
            coverage["partial"] += 1
        if row["source_artifact_uuid"] != "a726253a-edfa-5f2e-baa0-4c1d31af48ab":
            raise SystemExit("unexpected ASMB sibling-header artifact UUID")
    if coverage != {"full": 153, "partial": 6, "none": 28}:
        raise SystemExit(f"unexpected ASMB sibling-header coverage: {coverage}")


def source_text(rows: list[dict[str, str]]) -> str:
    fields = [k for k in rows[0] if k not in SEMANTIC_FIELDS] + list(SEMANTIC_FIELDS)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def module_text(rows: list[dict[str, str]], operations: list[dict]) -> str:
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
        + "\nASMB787_OPERATIONS = "
        + pprint.pformat(operations, width=100, sort_dicts=True)
        + "\n\n__all__ = ['ASMB787_COMMANDS', 'ASMB787_CMD_NAMES', 'ASMB787_OPERATIONS']\n"
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


def field_list(fields: list[dict] | None, layout: str, esc) -> str:
    if fields is None:
        tokens = [token.strip() for token in layout.split(";") if token.strip()]
        if not tokens:
            return '<span class="text-slate-400">No structured field map recovered.</span>'
        return ('<p class="text-slate-400">Variable or union layout; widths are not safely fixed.</p>'
                '<ul class="mt-1 list-disc pl-5">' + ''.join(
                    f'<li><code>{esc(token)}</code></li>' for token in tokens) + '</ul>')
    if not fields:
        return '<span class="text-slate-400">No fields.</span>'
    offset = 0
    items = []
    widths = {"u8": 1, "u16le": 2, "u32le": 4}
    for field in fields:
        width = field["length"] if "length" in field else widths[field["kind"]]
        detail = field["kind"]
        if "length" in field:
            detail += f"[{field['length']}]"
        if "constant" in field:
            detail += f" = 0x{field['constant']:02x}"
        byte_range = str(offset) if width == 1 else f"{offset}..{offset + width - 1}"
        items.append(
            f'<li><code>byte {byte_range}</code> · <code>{esc(field["name"])}</code>: '
            f'{esc(detail)}</li>'
        )
        offset += width
    return '<ul class="list-disc pl-5">' + ''.join(items) + '</ul>'


def operation_name(identifier: str) -> str:
    """Turn catalog identifiers into readable labels without changing identity."""
    head, *tail = identifier.replace("_", " ").split(".")
    head = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", head)
    head = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", head)
    head = re.sub(r"^(AMI)(YAFU)?", lambda match: " ".join(
        part for part in match.groups() if part) + " ", head)
    parts = [" ".join(head.split()), *(part.replace("_", " ") for part in tail)]
    return ": ".join(part for part in parts if part)


def operation_purpose(operation: dict) -> str:
    side_effects = operation["side_effects"]
    if side_effects.lower().startswith("none"):
        return (f"Queries {operation_name(operation['id'])}; response layout: "
                f"{operation['response']['layout']}.")
    return side_effects[0].upper() + side_effects[1:]


def doc_text(rows: list[dict[str, str]], operations: list[dict]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    by_key = {(int(row["netfn"], 0), int(row["cmd"], 0)): row for row in rows}
    effect_style = {
        "safe": "bg-emerald-950 text-emerald-200 ring-emerald-700",
        "mutates": "bg-amber-950 text-amber-200 ring-amber-700",
        "security-sensitive": "bg-pink-950 text-pink-200 ring-pink-700",
        "destructive": "bg-rose-950 text-rose-200 ring-rose-600",
    }
    effect_label = {"safe": "read-only", "mutates": "mutates",
                    "security-sensitive": "security-sensitive",
                    "destructive": "destructive"}
    body = []
    for row in rows:
        activation = row["activation_status"]
        status = activation_label(activation)
        effect = row["safety_tier"]
        search = " ".join(str(row[key]) for key in (
            "netfn", "cmd", "handler", "module", "privilege", "request_semantics",
            "response_semantics", "activation_status", "semantic_source", "safety_tier",
        )).lower()
        body.append(
            f"<tr class='border-b border-slate-800 align-top' data-search='{esc(search)}' data-effect='{esc(effect)}'>"
            f"<td class='p-2 font-mono'>{esc(row['netfn'])}/{esc(row['cmd'])}</td>"
            f"<th scope='row' class='p-2 text-left font-normal'><strong>{esc(row['handler'])}</strong><br><span class='text-slate-400'>{esc(row['module'])}</span></th>"
            f"<td class='p-2'>{esc(row['privilege'])} <span class='font-mono text-slate-400'>({esc(row['privilege_raw'])})</span></td>"
            f"<td class='p-2'>dispatcher +8 constraint: {esc(row['request_length_semantics'])}<br><span class='text-slate-400'>{esc(row['request_semantics'])}</span></td>"
            f"<td class='p-2'>{esc(row['response_semantics'])}</td>"
            f"<td class='p-2'>{esc(row['interface_semantics'])} <span class='font-mono text-slate-400'>({esc(row['interface_raw'])})</span></td>"
            f"<td class='p-2'><span class='inline-block rounded px-2 py-1 text-xs font-semibold ring-1 {effect_style[effect]}'>{esc(effect_label[effect])}</span></td>"
            f"<td class='p-2'><strong>{esc(status)}</strong><br><span class='text-slate-400'>{esc(activation)}</span></td>"
            f"<td class='p-2'>{esc(row['confidence'])}<br><span class='text-slate-400'>{esc(row['semantic_source'])}; {esc(row['semantic_confidence'])}</span></td>"
            "</tr>"
        )
    registered = sum(row["activation_status"].startswith("runtime registered:") for row in rows)
    skipped = sum(row["activation_status"].startswith("not runtime registered:") for row in rows)
    codecs = sum(operation["codec_state"] == "verified" for operation in operations)
    live_count = sum(bool(operation.get("live_evidence")) for operation in operations)
    effects = {effect: sum(operation["effect"] == effect for operation in operations)
               for effect in ("safe", "mutates", "security-sensitive", "destructive")}
    impact_lists = []
    for effect in ("destructive", "security-sensitive", "mutates"):
        matching = [operation for operation in operations if operation["effect"] == effect]
        items = []
        for operation in matching:
            netfn, cmd = operation["command"]
            items.append(
                f'<li><code>0x{netfn:02x}/0x{cmd:02x}</code> '
                f'<strong>{esc(operation_name(operation["id"]))}</strong> '
                f'<code>{esc(operation["id"])}</code> — {esc(operation_purpose(operation))}</li>'
            )
        impact_lists.append(
            f'<details class="mt-3"><summary class="font-semibold">{len(matching)} {esc(effect)} '
            f'operations</summary><ul class="mt-2 list-disc space-y-1 pl-6 text-sm">'
            f'{"".join(items)}</ul></details>'
        )
    operation_body = []
    for operation in operations:
        netfn, cmd = operation["command"]
        parent = by_key[(netfn, cmd)]
        prefix = operation.get("prefix")
        wire = f"0x{netfn:02x}/0x{cmd:02x}"
        if prefix is not None:
            wire += " " + " ".join(f"{byte:02x}" for byte in prefix)
        live = operation.get("live_evidence")
        live_text = "not live-tested"
        if live:
            live_text = (
                f"run {live['run_id']}; CC {live['completion_code']}; "
                f"data {live['response_data_hex'] or '(empty)'}"
            )
        effect = operation["effect"]
        display_name = operation_name(operation["id"])
        purpose = operation_purpose(operation)
        selector_text = operation.get("selectors")
        search = " ".join((wire, operation["id"], display_name, effect, purpose,
                           operation["request"]["layout"], operation["response"]["layout"],
                           parent["handler"], parent["module"], parent["activation_status"])).lower()
        request_fields = field_list(
            operation["request"].get("fields"), operation["request"]["layout"], esc)
        response_fields = field_list(
            operation["response"].get("fields"), operation["response"]["layout"], esc)
        safety = "read-only contract" if effect == "safe" else "--unsafe required"
        operation_body.append(
            f"<tr class='border-b border-slate-800 align-top' data-search='{esc(search)}' data-effect='{esc(effect)}'>"
            f"<td class='p-2 font-mono'>{esc(wire)}</td>"
            f"<th scope='row' class='min-w-72 p-2 text-left font-normal'><strong>{esc(display_name)}</strong>"
            f"<div class='mt-1 font-mono text-xs text-slate-400'>{esc(operation['id'])}</div>"
            f"<p class='mt-2 text-slate-300'><strong>Does:</strong> {esc(purpose)}</p>"
            f"{f'<p class=\"mt-1 text-xs text-slate-400\"><strong>Selectors:</strong> {esc(selector_text)}</p>' if selector_text else ''}</th>"
            f"<td class='min-w-96 p-2 text-xs'><strong>{esc(operation['request']['length'])} bytes:</strong> "
            f"<code>{esc(operation['request']['layout'])}</code><details><summary>Fields</summary>{request_fields}</details></td>"
            f"<td class='min-w-96 p-2 text-xs'><strong>{esc(operation['response']['length_including_cc'])} bytes including CC:</strong> "
            f"<code>{esc(operation['response']['layout'])}</code><details><summary>Fields</summary>{response_fields}</details></td>"
            f"<td class='min-w-72 p-2 text-xs'><span class='inline-block rounded px-2 py-1 font-semibold ring-1 {effect_style[effect]}'>{esc(effect_label[effect])}</span>"
            f"<p class='mt-2'><strong>Execution:</strong> {esc(safety)}<br><strong>Privilege:</strong> {esc(parent['privilege'])}"
            f"<br><strong>Activation:</strong> {esc(activation_label(parent['activation_status']))}</p>"
            f"<details><summary>Completion codes</summary><code>{esc(', '.join(operation['completion_codes']))}</code></details></td>"
            f"<td class='min-w-72 p-2 text-xs'><strong>Codec:</strong> {esc(operation['codec_state'])}"
            f"<br><strong>Handler:</strong> {esc(parent['handler'])}<br><strong>Evidence:</strong> {esc(operation['evidence']['location'])}"
            f"<br><strong>Confidence:</strong> {esc(operation['confidence'])}<br><strong>Live:</strong> {esc(live_text)}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Advantech ASMB-787 OEM IPMI command reference</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-950 text-slate-100"><main class="mx-auto max-w-[110rem] p-6">
<h1 class="text-3xl font-bold">Advantech ASMB-787 OEM IPMI command reference</h1>
<div class="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-6"><div class="rounded bg-blue-900/60 p-4"><strong class="text-2xl">{len(rows)}</strong><div>dispatch pairs</div></div><div class="rounded bg-blue-900/60 p-4"><strong class="text-2xl">{len(operations)}</strong><div>handler-proven operations</div></div><div class="rounded bg-emerald-900/60 p-4"><strong class="text-2xl">{codecs}</strong><div>fixed-width codecs</div></div><div class="rounded bg-emerald-900/60 p-4"><strong class="text-2xl">{live_count}</strong><div>live-backed operations</div></div><div class="rounded bg-amber-900/60 p-4"><strong class="text-2xl">{effects['safe']}</strong><div>read-only operations</div></div><div class="rounded bg-rose-900/60 p-4"><strong class="text-2xl">{effects['mutates'] + effects['security-sensitive'] + effects['destructive']}</strong><div>state-changing / sensitive</div></div></div>
<section class="mt-5 rounded border border-blue-700 bg-blue-950/50 p-4"><h2 class="font-bold">Coverage and limits</h2><p class="mt-2 text-slate-300">The 187-pair denominator is closed against this ASMB-787 firmware image. Each pair has an exact-target handler contract, but a named raw command is not necessarily a structured codec or a live-reachable plugin. Of 462 operations, {len(operations) - codecs} remain raw-exact because their framing cannot safely be represented by the fixed-width codec. Activation is distinguished below: 92 static, {registered} runtime-registered plugin, and {skipped} skipped plugin rows.</p></section>
<section class="mt-4 rounded border border-rose-800 bg-rose-950/40 p-4"><h2 class="font-bold">Safety boundary</h2><p class="mt-2 text-slate-300">The handler inventory includes {effects['mutates']} mutating, {effects['security-sensitive']} security-sensitive, and {effects['destructive']} destructive operations. Every operation is tagged and filterable below; expand these lists to see the exact commands and observed effects. zipmi requires <code>--unsafe</code> for named operations whose payload or effect is not proven safe.</p>{''.join(impact_lists)}</section>
<p class="mt-3 text-slate-300">Complete 187-entry firmware dispatch catalog and zipmi named raw surface for unique vendor NetFn/Cmd pairs. Evidence separates 92 statically registered core/platform rows, {registered} runtime-registered plugin rows, and {skipped} plugin rows skipped because their exact feature token is absent. The CmdHndlr_T layout is <code>cmd@+0</code>, <code>privilege@+1</code>, <code>handler@+4</code>, the one-byte dispatcher request-length constraint at <code>+8</code>, and <code>interface@+12</code>. Earlier documentation swapped privilege and request length.</p>
<p class="mt-2 text-slate-300">A named command means zipmi can emit its exact NetFn/Cmd bytes. It does not claim a structured codec, complete request/response semantics, or runtime reachability. The +8 value proves only the dispatcher constraint shown; payload fields remain explicitly unknown unless AMI client/header material supplies labelled context. Type-8 secondary selector hooks exist, but their selector values remain unknown.</p>
<section class="mt-8"><h2 class="text-2xl font-semibold">Exact-target operation contracts</h2>
<p class="mt-2 text-slate-300">Exact handler decompilation currently proves {len(operations)} operations across {len({tuple(operation['command']) for operation in operations})} command pairs. zipmi generates structured fixed-width codecs for {sum(operation['codec_state'] == 'verified' for operation in operations)} operations; the remaining {sum(operation['codec_state'] != 'verified' for operation in operations)} retain exact raw contracts because their variable, union, checksum, or overlapping-bitmask framing needs a dedicated codec. The analyzed firmware is artifact <code>379c676d-4d49-52ea-a268-541c391a69ca</code>.</p>
<div class="mt-4 grid gap-3 md:grid-cols-[1fr_16rem]"><label><span class="font-semibold">Filter operations</span><input id="operation-filter" class="mt-2 w-full rounded border border-slate-700 bg-slate-900 p-3" placeholder="name, wire, action, handler, module"></label><label><span class="font-semibold">Safety class</span><select id="effect-filter" class="mt-2 w-full rounded border border-slate-700 bg-slate-900 p-3"><option value="">All safety classes</option><option value="safe">Read-only</option><option value="mutates">Mutates</option><option value="security-sensitive">Security-sensitive</option><option value="destructive">Destructive</option></select></label></div>
<p id="operation-count" class="mt-3 text-sm text-slate-400" aria-live="polite"></p><div class="mt-4 overflow-x-auto" role="region" aria-label="Advantech exact operation contracts" tabindex="0"><table class="w-full text-sm"><caption class="pb-3 text-left text-slate-300">Handler-proven requests, responses, effects, activation, codecs, and live evidence.</caption><thead class="sticky top-0 bg-slate-900 text-left"><tr><th class="p-2">Wire / prefix</th><th class="p-2">Operation / purpose</th><th class="p-2">Request</th><th class="p-2">Response</th><th class="p-2">Safety / activation</th><th class="p-2">zipmi / evidence</th></tr></thead><tbody id="operation-rows">{''.join(operation_body)}</tbody></table></div></section>
<section class="mt-8"><h2 class="text-2xl font-semibold">Top-level firmware dispatch</h2>
<div class="mt-4 grid gap-3 md:grid-cols-[1fr_16rem]"><label><span class="font-semibold">Filter top-level commands</span><input id="dispatch-filter" class="mt-2 w-full rounded border border-slate-700 bg-slate-900 p-3" placeholder="wire, handler, module, privilege, activation"></label><label><span class="font-semibold">Worst operation class</span><select id="dispatch-effect-filter" class="mt-2 w-full rounded border border-slate-700 bg-slate-900 p-3"><option value="">All safety classes</option><option value="safe">Read-only</option><option value="mutates">Mutates</option><option value="security-sensitive">Security-sensitive</option><option value="destructive">Destructive</option></select></label></div><p id="dispatch-count" class="mt-3 text-sm text-slate-400" aria-live="polite"></p><div class="mt-6 overflow-x-auto" role="region" aria-label="Advantech top-level dispatch" tabindex="0"><table class="w-full text-sm"><caption class="pb-3 text-left text-slate-300">All 187 unique ASMB-787 vendor NetFn/Cmd catalog entries and their evidence boundaries.</caption><thead class="sticky top-0 bg-slate-900 text-left"><tr><th scope="col" class="p-2">Wire</th><th scope="col" class="p-2">Handler / module</th><th scope="col" class="p-2">Privilege</th><th scope="col" class="p-2">Request</th><th scope="col" class="p-2">Response</th><th scope="col" class="p-2">Interface</th><th scope="col" class="p-2">Worst operation class</th><th scope="col" class="p-2">Activation</th><th scope="col" class="p-2">Evidence / confidence</th></tr></thead><tbody id="dispatch-rows">""" + "".join(body) + """</tbody></table></div>
</section>
<p class="mt-6 text-slate-400">Generated from <code>zipmi/data/sources/advantech-asmb787-oem-dispatch.csv</code> by <code>scripts/generate_advantech_asmb787.py</code>.</p>
</main><script>const operationFilter=document.getElementById('operation-filter'),effectFilter=document.getElementById('effect-filter'),operationRows=[...document.querySelectorAll('#operation-rows tr')],operationCount=document.getElementById('operation-count');function filterOperations(){const query=operationFilter.value.toLowerCase(),effect=effectFilter.value;let visible=0;for(const row of operationRows){row.hidden=!row.dataset.search.includes(query)||(effect&&row.dataset.effect!==effect);if(!row.hidden)visible++;}operationCount.textContent=`${visible} of ${operationRows.length} operations shown`;}operationFilter.addEventListener('input',filterOperations);effectFilter.addEventListener('change',filterOperations);filterOperations();const dispatchFilter=document.getElementById('dispatch-filter'),dispatchEffectFilter=document.getElementById('dispatch-effect-filter'),dispatchRows=[...document.querySelectorAll('#dispatch-rows tr')],dispatchCount=document.getElementById('dispatch-count');function filterDispatch(){const query=dispatchFilter.value.toLowerCase(),effect=dispatchEffectFilter.value;let visible=0;for(const row of dispatchRows){row.hidden=!row.dataset.search.includes(query)||(effect&&row.dataset.effect!==effect);if(!row.hidden)visible++;}dispatchCount.textContent=`${visible} of ${dispatchRows.length} commands shown`;}dispatchFilter.addEventListener('input',filterDispatch);dispatchEffectFilter.addEventListener('change',filterDispatch);filterDispatch();</script></body></html>
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
    validate_header_context(rows)
    operations = apply_contracts(rows)
    ok = emit(SOURCE, source_text(rows), args.check)
    ok &= emit(MODULE, module_text(rows, operations), args.check)
    ok &= emit(DOC, doc_text(rows, operations), args.check)
    ok &= emit(DOC_MD, markdown_text(rows), args.check)
    if args.check and not ok:
        print("ASMB-787 generated files are stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
