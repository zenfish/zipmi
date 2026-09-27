#!/usr/bin/env python3
"""Import and generate the Advantech ASMB-787 OEM command catalog."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
import io
import json
import pprint
import re
import sys
from pathlib import Path

from oem_reference import redirect_page, render_reference


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-oem-dispatch.csv"
ACTIVATION_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-module-activation.csv"
CONTRACTS_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-oem-contracts.json"
HEADER_SOURCE = ROOT / "zipmi/data/sources/advantech-asmb787-header-contracts.csv"
MODULE = ROOT / "zipmi/scapy_ipmi/oem/advantech_asmb787_generated.py"
DOC = ROOT / "docs/advantech-asmb787-command-reference.html"
LEGACY_DOC = ROOT / "docs/advantech_ASMB787-command-reference.html"
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

DISRUPTIVE_OPERATIONS = {
    "AMIPTPCtrl.stop", "AMIPTPCtrl.restart", "AMISetKCSLANIfcSupport.kcs",
    "AMISetKCSLANIfcSupport.lan", "AMIRISStartStop",
    "AMIMediaRedirectionStartStop", "AMIActiveSessionClose",
    "AMIRestartWebService", "AMIYAFUResetDevice",
    "AMISetIfaceState.ethernet_state", "AMISetIfaceState.bond_state",
    "AMISetIfaceState.bond_enabled", "AMISetIfaceState.bond_active_slave",
    "AMISetIfaceState.bond_vlan_enabled",
}
DESTRUCTIVE_OPERATIONS = {
    "AMIGetMediaInfo", "AMISetFirewall", "AMIGetRAIDInfo.clear_event_log",
    "AMIGetRAIDInfo.clear_sasit_event_log", "AMIGetRAIDInfo.clear_foreign_device",
}
SENSITIVE_OPERATIONS = {
    "PDK_SDRGetAnalogFlags", "AMIFileDownload", "AMIFileUpload",
    "AMISetPswdChangeStatus", "AMIResetPassword", "AMISetRootPassword",
    "AMISetUserShelltype", "AMISetLoginAuditConfig", "AMISetSSLCert",
    "AMISetDNSConf.tsig_upload", "AMISetFWCfg", "AMISetFWProtocol",
    "AMIPLDMFIRMWAREMsg.request_update", "AMIPLDMFIRMWAREMsg.pass_component_table",
    "AMIFirmwareCommand.set_update_mode", "AMIFirmwareCommand.set_network_share",
    "AMIFirmwareCommand.set_share_operation", "AMIFirmwareCommand.set_update_component",
    "AMIFirmwareCommand.set_status_by_bios", "AMIFirmwareCommand.cancel_component_update",
    "AMIFirmwareCommand.rearm_firmware_timer", "AMIYAFUActivateFlashMode",
    "AMIYAFUAllocateMemory", "AMIYAFUFreeMemory", "AMIYAFUProtectFlash",
    "AMIYAFUSetBootConfig", "AMIYAFUDeactivateFlash", "AMIYAFUSwitchFlashDevice",
    "AMIYAFURestoreFlashDevice", "AMIYAFUDualImgSup", "AMIYAFUFWSelectFlash",
    "AMIYAFUActivateFlashDevice", "AMIYAFUReplaceSignedImageKey",
    "AMIGetUDSSessionInfo.session_counts", "AMIGetUDSSessionInfo.session_by_id",
    "AMIGetUDSSessionInfo.session_by_handle", "AMIGetUDSSessionInfo.session_by_index",
    "AMIGetUDSSessionInfo.session_by_user", "AMIGetUDSSessionInfo.process_thread_ids",
    "AMIGetUDSSessionInfo.active_indices", "SetSMTPConfigParams.username",
    "SetSMTPConfigParams.password", "SetSMTPConfigParams.username2",
    "SetSMTPConfigParams.password2", "SetSMTPConfigParams.auth_enable",
    "SetSMTPConfigParams.auth2_enable", "SetSMTPConfigParams.starttls",
    "SetSMTPConfigParams.starttls2", "SetSMTPConfigParams.ssltls",
    "SetSMTPConfigParams.ssltls2",
    *(f"AMIGetAllActiveSessions.type_{index}" for index in range(7)),
}
STATE_CHANGING_OPERATIONS = {
    "AMISensorThresholdAcrossResets.restore", "AMISetRemoteKVMCfg.mouse_mode",
    "AMISetRemoteKVMCfg.keyboard_layout", "AMISetRemoteKVMCfg.retry_count",
    "AMISetRemoteKVMCfg.retry_interval", "AMISetRunTimeSinglePortStatus",
}
UNKNOWN_OPERATIONS = {
    "ControlMEUpdate.action_0", "ControlMEUpdate.action_1", "LockInputs.action_f0",
    "LockInputs.action_f1", "ControlSysErrLED.action_0", "ControlSysErrLED.action_1",
    "AMIYAFUGetImgSize", "AMIPLDMFIRMWAREMsg.cancel_update_component",
    "AMIPLDMFIRMWAREMsg.cancel_update", "AMIGetDNSConf.reserved_10",
    "SetSMTPConfigParams.reserved_28", "SetSMTPConfigParams.reserved_29",
    "GetSMTPConfigParams.reserved_28", "GetSMTPConfigParams.reserved_29",
}
MIXED_BEHAVIOR_OPERATIONS = {
    "AMIGetMediaInfo", "AMISetFirewall", "AMISetKCSLANIfcSupport.kcs",
    "AMISetKCSLANIfcSupport.lan", "AMIRISStartStop",
    "AMIMediaRedirectionStartStop", "AMISetIfaceState.ethernet_state",
    "AMISetIfaceState.bond_state", "AMISetIfaceState.bond_enabled",
    "AMISetIfaceState.bond_active_slave", "AMISetIfaceState.bond_vlan_enabled",
}


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
        match = re.fullmatch(r"([A-Za-z_]\w*)\((one bit)\)", token)
        if match:
            fields.append({"name": match.group(1), "kind": "u8",
                           "meaning": match.group(2)})
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


def safety_class(operation: dict) -> str:
    identifier = operation["id"]
    overrides = (
        (DISRUPTIVE_OPERATIONS, "disruptive"),
        (DESTRUCTIVE_OPERATIONS, "destructive"),
        (SENSITIVE_OPERATIONS, "sensitive"),
        (STATE_CHANGING_OPERATIONS, "state-changing"),
        (UNKNOWN_OPERATIONS, "unknown"),
    )
    for identifiers, classification in overrides:
        if identifier in identifiers:
            return classification
    return {
        "safe": "read-only",
        "mutates": "state-changing",
        "security-sensitive": "sensitive",
        "destructive": "destructive",
    }[operation["effect"]]


def layout_status(fields: list[dict] | None, layout: str) -> str:
    if fields is not None:
        return "Complete"
    if any(word in layout.lower() for word in ("unknown", "unresolved")):
        return "Unknown"
    return "Partial"


def normalized_fields(fields: list[dict] | None, *, response: bool = False) -> list[dict] | None:
    if fields is None:
        return None
    source = fields[1:] if response and fields and fields[0]["name"] == "completion_code" else fields
    result = []
    offset = 0
    widths = {"u8": 1, "u16le": 2, "u32le": 4}
    for field in source:
        width = field["length"] if "length" in field else widths[field["kind"]]
        meaning = (f"Must be 0x{field['constant']:02x}" if "constant" in field
                   else field.get("meaning", "See operation semantics"))
        result.append({
            "offset": str(offset) if width == 1 else f"{offset}–{offset + width - 1}",
            "name": field["name"],
            "type": f"bytes[{width}]" if field["kind"] == "bytes" else field["kind"],
            "meaning": meaning,
        })
        offset += width
    return result


def response_length(value: str) -> str:
    if value.isdigit():
        return f"{max(0, int(value) - 1)} data bytes after completion code"
    return f"{value} including completion code; data length unresolved"


def request_argument_tokens(operation: dict, skip_bytes: int = 0) -> list[str]:
    """Render caller-supplied request bytes after an optional named-route prefix."""
    request = operation["request"]
    fields = request.get("fields")
    if fields is not None:
        tokens = []
        widths = {"u8": 1, "u16le": 2, "u32le": 4}
        for field in fields:
            width = field["length"] if "length" in field else widths[field["kind"]]
            if skip_bytes >= width:
                skip_bytes -= width
                continue
            if skip_bytes:
                tokens.append(f"<{width - skip_bytes} remaining bytes of {field['name']}>")
                skip_bytes = 0
                continue
            if "constant" in field:
                tokens.append(f"0x{field['constant']:02x}")
            elif field["kind"] == "bytes":
                tokens.append(f"<{field['name']}:{field['length']} bytes>")
            else:
                tokens.append(f"<{field['name']}:{field['kind']}>")
        return tokens
    prefix = operation.get("prefix") or []
    tokens = [f"0x{value:02x}" for value in prefix[skip_bytes:]]
    if request["length"].isdigit():
        remaining = int(request["length"]) - max(len(prefix), skip_bytes)
        if remaining > 0:
            tokens.append(f"<{remaining} remaining data bytes>")
    else:
        tokens.append("<payload bytes>")
    return tokens


def zipmi_command(operation: dict, parent: dict, execution: str) -> str:
    """Prefer the supported named OEM route; fall back to an explicit raw request."""
    prefix = operation.get("prefix")
    if execution != "No distinct named route":
        name = operation["id"] if prefix is not None else parent["handler"]
        tokens = ["zipmi", "oem", "advantech-asmb787"]
        if execution == "Requires --unsafe":
            tokens.append("--unsafe")
        tokens.append(name)
        tokens.extend(request_argument_tokens(operation, len(prefix or [])))
        return " ".join(tokens)
    netfn, cmd = operation["command"]
    tokens = ["zipmi", "raw", f"0x{netfn:02x}", f"0x{cmd:02x}"]
    tokens.extend(request_argument_tokens(operation))
    return " ".join(tokens)


def availability(value: str) -> str:
    if value == "statically registered in owning dispatcher table":
        return "Built into the main IPMI service"
    if value.startswith("runtime registered:"):
        return "Registered automatically when the IPMI service starts"
    if value.startswith("not runtime registered:"):
        return "Present on disk but not registered; feature disabled"
    if "explicitly enabled" in value:
        return "Enabled in this firmware; startup registration not proved"
    if "absent from extracted" in value:
        return "Disabled in this firmware"
    raise SystemExit(f"unknown activation status: {value}")


def privilege(value: str) -> str:
    if value.startswith("special/raw "):
        return f"Access requirement unknown (firmware value {value.removeprefix('special/raw ')})"
    return value


def compatibility_markdown() -> str:
    return """# Advantech ASMB-787 OEM IPMI command reference

The canonical human-readable reference is
[the HTML command reference](advantech-asmb787-command-reference.html).

This compatibility pointer replaces the former duplicate Markdown table. The generated CSV and
JSON files under `zipmi/data/sources/` remain the machine-readable sources of truth.
"""


def reference_page(rows: list[dict[str, str]], operations: list[dict]) -> dict:
    by_key = {(int(row["netfn"], 0), int(row["cmd"], 0)): row for row in rows}
    operation_counts = Counter(tuple(operation["command"]) for operation in operations)
    rendered_operations = []
    for operation in operations:
        netfn, cmd = operation["command"]
        parent = by_key[(netfn, cmd)]
        prefix = operation.get("prefix")
        live = operation.get("live_evidence")
        sole_unprefixed = prefix is None and operation_counts[(netfn, cmd)] == 1
        executable = prefix is not None or sole_unprefixed
        if not executable:
            execution = "No distinct named route"
        elif prefix is not None:
            execution = ("Allowed by default" if operation["effect"] == "safe"
                         else "Requires --unsafe")
        else:
            execution = ("Allowed by default" if parent["safety_tier"] == "safe"
                         and parent["request_length_raw"] != "0xff"
                         and parent["semantic_confidence"] == "target-proven"
                         else "Requires --unsafe")
        purpose = operation_purpose(operation)
        if operation["id"] in UNKNOWN_OPERATIONS:
            purpose += " The external effect is not established by current evidence."
        request = operation["request"]
        response = operation["response"]
        request_fields = normalized_fields(request.get("fields"))
        response_fields = normalized_fields(response.get("fields"), response=True)
        if operation["id"] == "AMIGetRISConf":
            request_fields[0]["meaning"] = ("Exactly one configured remote-image slot: "
                                             "0x01, 0x02, 0x04, 0x08, or 0x10")
            request_fields[1]["meaning"] = ("0x00 image; 0x01 path; 0x02 host; 0x03 user; "
                                             "0x04 password; 0x05 share type; 0x06 domain; "
                                             "0x07 retry; 0x08 interval; 0x09 mounted; "
                                             "0x0a service status")
            response_fields = [
                {"offset": "0", "name": "media_mask", "type": "u8",
                 "meaning": "Echoed remote-image slot mask"},
                {"offset": "1", "name": "selector", "type": "u8",
                 "meaning": "Echoed selector from the request"},
                {"offset": "2…", "name": "value", "type": "selector-dependent",
                 "meaning": ("Selected value: image/path/user/domain 256 bytes; host 63; "
                             "password 32 zero bytes; share type 6; retry/interval/mounted/"
                             "service status 1")},
            ]
        rendered_operations.append({
            "id": operation["id"],
            "send": zipmi_command(operation, parent, execution),
            "name": operation_name(operation["id"]),
            "purpose": purpose,
            "safety": safety_class(operation),
            "safety_note": ("Combined firmware behavior; class reflects the highest known impact."
                            if operation["id"] in MIXED_BEHAVIOR_OPERATIONS else ""),
            "execution": execution,
            "request": {
                "status": layout_status(request.get("fields"), request["layout"]),
                "length": f'{request["length"]} payload bytes',
                "summary": request["layout"],
                "fields": request_fields,
            },
            "response": {
                "status": layout_status(response.get("fields"), response["layout"]),
                "length": response_length(response["length_including_cc"]),
                "summary": response["layout"].removeprefix("cc;") or "no response data",
                "fields": response_fields,
            },
            "privilege": privilege(parent["privilege"]),
            "interface": parent["interface_semantics"],
            "availability": availability(parent["activation_status"]),
            "completion_codes": ", ".join(operation["completion_codes"]),
            "live": bool(live),
            "live_text": (f'{live["run_id"]}; CC {live["completion_code"]}; data '
                          f'{live["response_data_hex"] or "(empty)"}' if live else "Not live-tested"),
            "evidence": operation["evidence"]["location"],
            "confidence": operation["confidence"],
        })
    rendered_commands = [{
        "wire": f'{row["netfn"]}/{row["cmd"]}',
        "handler": row["handler"],
        "module": row["module"],
        "availability": availability(row["activation_status"]),
        "privilege": privilege(row["privilege"]),
        "operation_count": operation_counts[(int(row["netfn"], 0), int(row["cmd"], 0))],
        "evidence": f'{row["table"]} entry {row["entry_address"]}; SHA-256 {row["module_sha256"]}',
    } for row in rows]
    return {
        "artifact_marker": "bbe82df6-3df8-4103-8612-72b359a7fdda generated",
        "title": "Advantech ASMB-787 OEM IPMI command reference",
        "scope": ("Firmware-bound reference for every recovered OEM command address and distinct "
                  "handler operation in Advantech ASMB-787 firmware 20220912."),
        "provenance": [
            ("Controller", "Advantech ASMB-787"),
            ("Firmware", "AMI MegaRAC SP-X 4.0; build 2022-09-12 01:11:56 UTC; identifier 20220912"),
            ("Platform", "ASPEED AST2600 ARMv7; Linux 5.4.11-ami"),
            ("Firmware artifact", "<code>encrypted_ASMB-787_20220912.ima_enc</code> (67,109,128 bytes)"),
            ("Firmware SHA-256", "<code>3e9916fd633babe11c208c0982330f8677e4f3b05029653a56ffe4230dea1cbd</code>"),
            ("Research artifact ID", "<code>379c676d-4d49-52ea-a268-541c391a69ca</code> — stable registry identity; unlike SHA-256, it remains attached when the research artifact is revised"),
            ("Firmware source commit", "<code>bd7acc8f7a95e0ffc284d85ef6bd76bc61d4a2c4</code>; BuildScript 5.8.0"),
        ],
        "links": [{
            "label": "zBMC firmware analysis and emulation notes",
            "href": "https://github.com/zenfish/zbmc/blob/main/boxes/advantech-asmb787/index.html",
        }],
        "operations": rendered_operations,
        "commands": rendered_commands,
        "gaps": ("The 187-address inventory is closed for this firmware. One address is one unique "
                 "NetFn/Cmd pair; several payload-selected operations can share an address. "
                 "Variable, union, checksum, and selector-dependent layouts remain Partial. "
                 "Combined behaviors are not split unless their selector boundary is proven."),
        "live_evidence": ("33 of 462 operations have captured requests and responses from the emulated "
                          "firmware: 32 are classified read-only and one is classified sensitive because its "
                          "handler can expose an uninitialized byte. The others were not exercised when they "
                          "change state, affect security, are disruptive or destructive, have unknown effects, "
                          "lack a safely constructible request, or are not loaded in this firmware. Live "
                          "evidence proves only the exact recorded transactions."),
        "sources": [
            '<a href="../zipmi/data/sources/advantech-asmb787-oem-dispatch.csv">Top-level firmware dispatch CSV</a>',
            '<a href="../zipmi/data/sources/advantech-asmb787-oem-contracts.json">Operation-contract JSON</a>',
            '<a href="../zipmi/data/sources/advantech-asmb787-module-activation.csv">Module availability CSV</a>',
            '<a href="../zipmi/data/sources/advantech-asmb787-header-contracts.csv">Sibling-header context CSV</a>',
        ],
    }


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
    ok &= emit(DOC, render_reference(reference_page(rows, operations)), args.check)
    ok &= emit(LEGACY_DOC, redirect_page(
        "Advantech ASMB-787 OEM IPMI command reference",
        DOC.name,
    ), args.check)
    ok &= emit(DOC_MD, compatibility_markdown(), args.check)
    if args.check and not ok:
        print("ASMB-787 generated files are stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
