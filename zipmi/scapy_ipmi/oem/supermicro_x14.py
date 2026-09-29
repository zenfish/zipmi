# z-artifact: ec8dde41-8f9a-4538-9d30-be9d495f9344
"""Firmware-bound Supermicro X14SBSC-RoT / E601MS OEM IPMI support.

The source catalog closes the five provider ELFs in BMC firmware 01.01.06.07.
This module exposes Supermicro raw, selector, group-extension, and RAS
operations.  The 11 bundled Intel Node Manager commands remain owned by
``intel.py``; standard overrides stay in ``X14_REGISTRATIONS`` for inventory
and documentation rather than being duplicated as OEM commands.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ._registry import build_fixed_packet_class, register


X14_FIRMWARE_SHA256 = "8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792"
X14_ROOTFS_SHA256 = "d9767ced6fc5301ae02d1fb918314bc1c182c6de4baac2376b3914a0a1eb8afa"
X14_PRIMARY_PROVIDER_SHA256 = "980527b4d95e8fdf07ae7f4afc0f9680017e9d3ccaeca59c877e0de9c335a1ad"
X14_PRIMARY_PROVIDER_BUILD_ID = "6f0189859aa536e9c2e1684915d57608dee9f150"

_SOURCE = Path(__file__).parents[2] / "data/sources/supermicro-x14-contracts.json"
X14_CATALOG = json.loads(_SOURCE.read_text())
if X14_CATALOG["firmware"]["image_sha256"] != X14_FIRMWARE_SHA256:
    raise RuntimeError("Supermicro X14 catalog does not match the pinned firmware")

_PRIMARY = X14_CATALOG["primary"]
_AUXILIARY = X14_CATALOG["auxiliary"]
_PRIVILEGE = {0: "None", 1: "Callback", 2: "User", 3: "Operator", 4: "Administrator"}
_PARENT_DISPATCHERS = {(0x30, command) for command in (0x51, 0x68, 0x70, 0xA0, 0xAD)}


def _number(value: int | str) -> int:
    return value if isinstance(value, int) else int(value, 0)


def _fields(fields: list[dict] | list[str] | None) -> list[dict] | None:
    if fields is None:
        return None
    normalized = []
    for index, field in enumerate(fields):
        if isinstance(field, str):
            normalized.append({
                "offset": "var" if index else "0", "name": f"field{index}",
                "type": "see meaning", "meaning": field,
            })
            continue
        meaning = field.get("meaning") or "Recovered typed field"
        if "value" in field and f"{field['value']}" not in meaning:
            meaning = f"fixed {field['value']}; {meaning}"
        values = field.get("values") or field.get("constraints")
        if isinstance(values, dict):
            detail = "; ".join(f"{key} = {value}" for key, value in values.items())
            meaning = f"{meaning}; {detail}"
        elif isinstance(values, str) and values != str(field.get("value", "")) and values not in meaning:
            meaning = f"{meaning}; constraints: {values}"
        normalized_field = {
            "offset": str(field.get("offset", index)),
            "name": field.get("name", f"field{index}"),
            "type": field.get("type", "bytes"),
            "meaning": meaning,
        }
        if "value" in field:
            normalized_field["value"] = field["value"]
        normalized.append(normalized_field)
    return normalized


def _codes(value: list[str] | dict[str, str] | str | None) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "; ".join(f"0x{code} {meaning}" for code, meaning in value.items())
    return "; ".join(value or ()) or "No handler-specific code recovered"


def _primary_safety(handler: str, status: str, effects: str) -> str:
    text = f"{handler} {effects}".lower()
    if any(word in text for word in ("password", "credential", "secret", "hash key", "certificate", "raw memory")):
        return "sensitive"
    if any(word in text for word in ("factory default", "restorefru", "restoresdr", "erase", "delete file")):
        return "destructive"
    if any(word in text for word in ("power cycle", "power off", "reboot", "reset bmc")):
        return "disruptive"
    if status == "authenticated-read-query":
        return "read-only"
    return "state-changing"


def _evidence(entry: dict) -> str:
    evidence = entry.get("evidence", {})
    body = entry.get("body_analysis", {})
    parts = []
    for name in ("constructor_callsite", "register_call", "selector_store", "map_builder_raw"):
        if evidence.get(name):
            parts.append(f"{name} {evidence[name]}")
    if body.get("address"):
        parts.append(f"target handler body {body['address']}")
    return "; ".join(parts) or "Pinned target provider decompilation"


def _primary_operation(entry: dict) -> tuple[tuple[int, ...], dict]:
    netfn, command = _number(entry["netfn"]), _number(entry["command"])
    selector = _number(entry["selector"])
    request, response = entry["request"], entry["response"]
    status = entry["runnable_status"]
    return (netfn, command, selector), {
        "name": entry["handler"], "handler": entry["handler"],
        "purpose": entry.get("purpose", entry["effects"]), "privilege": _PRIVILEGE[entry["privilege"]],
        "request_length": (request["minimum_bytes_including_selector"], request["maximum_bytes_including_selector"]),
        "response_length": (response["minimum_bytes"], response["maximum_bytes"]),
        "request_fields": _fields(request["fields"]),
        "response_fields": _fields(response["fields"]),
        "completion_codes": _codes(entry["completion_codes"]),
        "activation": entry["activation"], "side_effects": entry["effects"],
        "safety": entry.get("safety_class", _primary_safety(entry["handler"], status, entry["effects"])),
        "safety_note": entry.get("semantic_safety_note", entry["effects"]),
        "confidence": entry["confidence"], "evidence": _evidence(entry),
        "semantic_unresolved_reason": entry.get("semantic_unresolved_reason"),
        "prefix": bytes([selector]), "selector": bytes([selector]),
        "selector_offset": entry["selector_offset"],
        "owner": "Supermicro primary provider", "runnable": entry.get("execution_supported", True), "live": None,
    }


def _primary_direct(entry: dict) -> tuple[tuple[int, int], dict] | None:
    netfn, command = _number(entry["netfn"]), _number(entry["command"])
    if entry["classification"] != "raw" or (netfn, command) in _PARENT_DISPATCHERS:
        return None
    request, response = entry["request"], entry["response"]
    status = entry["runnable_status"]
    return (netfn, command), {
        "name": entry["handler"], "handler": entry["handler"],
        "purpose": entry.get("purpose", entry["effects"]), "privilege": entry["privilege_name"],
        "request_length": (request["wire_minimum_bytes"], request["wire_maximum_bytes"]),
        "response_length": (response["minimum_bytes"], response["maximum_bytes"]),
        "request_fields": _fields(request["fields"]),
        "response_fields": _fields(response["fields"]),
        "completion_codes": _codes(entry["completion_codes"]),
        "activation": entry["activation"], "side_effects": entry["effects"],
        "safety": entry.get("safety_class", _primary_safety(entry["handler"], status, entry["effects"])),
        "safety_note": entry.get("semantic_safety_note", entry["effects"]),
        "confidence": entry["confidence"], "evidence": _evidence(entry),
        "semantic_unresolved_reason": entry.get("semantic_unresolved_reason"),
        "owner": "Supermicro primary provider", "runnable": True, "live": None,
    }


def _manual_command(
    key: tuple[int, ...], *, name: str, handler: str, purpose: str,
    privilege: str, request_length: tuple[int | None, int | None],
    response_length: tuple[int | None, int | None], request_fields: list,
    response_fields: list, completion_codes: object, activation: str,
    safety: str, owner: str, evidence: str, runnable: bool = True,
) -> tuple[tuple[int, ...], dict]:
    return key, {
        "name": name, "handler": handler, "purpose": purpose,
        "privilege": privilege, "request_length": request_length,
        "response_length": response_length,
        "request_fields": _fields(request_fields), "response_fields": _fields(response_fields),
        "completion_codes": _codes(completion_codes), "activation": activation,
        "side_effects": purpose, "safety": safety,
        "confidence": "Exact target-body contract", "evidence": evidence,
        "prefix": bytes(key[2:]) if len(key) > 2 else None,
        "owner": owner, "runnable": runnable, "live": None,
    }


def _wire_field(offset: str | int, name: str, kind: str, meaning: str) -> dict:
    return {"offset": str(offset), "name": name, "type": kind, "meaning": meaning}


def _auxiliary_commands() -> list[tuple[tuple[int, ...], dict]]:
    rows = []
    ras_fields = {
        0x22: ([], [
            _wire_field(0, "upi_ce_supported", "u8 bitfield", "bits0:3 reserved zero; bits4:7 UPI corrected-error support"),
            _wire_field(1, "mem_ce_supported", "u8", "Memory corrected-error support"),
            _wire_field(2, "spd_recovery", "u8", "SPD recovery support/state"),
            _wire_field(3, "pcie_ce_supported", "u8", "PCIe corrected-error support"),
        ]),
        0x23: ([
            _wire_field("0–end", "policy_data", "byte vector", "Opaque policy data forwarded to RasSetData; element semantics are not exposed by this provider"),
        ], [
            _wire_field("0–end", "result_data", "byte vector", "Opaque byte vector returned by RasSetData"),
        ]),
        0x24: ([
            _wire_field("0–3", "start_control", "u32le", "Opaque start/control argument forwarded to RasStart"),
        ], []),
    }
    for source in _AUXILIARY["ras"]["contracts"]:
        command = _number(source["command"])
        request_length = source["request"]["length"]
        request_bounds = (0, None) if isinstance(request_length, str) else (request_length, request_length)
        response_length = source["response"]["length"]
        response_bounds = (0, None) if isinstance(response_length, str) else (response_length, response_length)
        rows.append(_manual_command(
            (0x32, command), name=source["handler"], handler=source["handler"],
            purpose=source["effects"], privilege="Administrator",
            request_length=request_bounds, response_length=response_bounds,
            request_fields=ras_fields[command][0], response_fields=ras_fields[command][1],
            completion_codes=source["completion_codes"], activation=_AUXILIARY["ras"]["activation"],
            safety="read-only" if command == 0x22 else "state-changing",
            owner="Supermicro X14 RAS provider", evidence=source["evidence"],
        ))

    groups = {(source["group"], source["command"]): source
              for source in _AUXILIARY["primary_group_handlers"]}
    group_fields = {
        (0x52, 0x01): ([
            _wire_field(1, "certificate_number", "u8", "1-based certificate number"),
        ], [
            _wire_field(1, "hash_algorithm", "u8", "0x01 = SHA-256"),
            _wire_field("2–33", "fingerprint", "bytes[32]", "SHA-256 certificate fingerprint"),
        ]),
        (0x52, 0x02): ([
            _wire_field(1, "disable_control", "u8", "0xa5 keeps bootstrapping enabled; any other value disables it after success"),
        ], [
            _wire_field("1–16", "username", "bytes[16]", "NUL-padded UTF-8 bootstrap username"),
            _wire_field("17–32", "password", "bytes[16]", "NUL-padded UTF-8 bootstrap password"),
        ]),
        (0xDC, 0x07): ([
            _wire_field(1, "sensor_type", "u8", "DCMI sensor type; target accepts 0x01"),
            _wire_field(2, "entity_id", "u8", "Entity ID"),
            _wire_field(3, "entity_instance", "u8", "0x00 requests all instances"),
            _wire_field(4, "entity_instance_start", "u8", "First entity instance to return"),
        ], [
            _wire_field(1, "total_instances", "u8", "Total matching entity instances"),
            _wire_field(2, "record_count", "u8", "Number of record IDs that follow; maximum 8 for an all-instance query"),
            _wire_field("3–end", "record_ids", "record_count × u16le", "SDR record IDs"),
        ]),
        (0xDC, 0x10): ([
            _wire_field(1, "sensor_type", "u8", "DCMI sensor type"),
            _wire_field(2, "entity_id", "u8", "Entity ID"),
            _wire_field(3, "entity_instance", "u8", "0x00 requests all instances"),
            _wire_field(4, "entity_instance_start", "u8", "First entity instance to return"),
        ], [
            _wire_field(1, "total_instances", "u8", "Total matching entity instances"),
            _wire_field(2, "reading_count", "u8", "Number of two-byte reading records that follow"),
            _wire_field("3–end", "readings", "reading_count × 2 bytes", "Temperature bits0:6 and sign bit7, followed by entity instance"),
        ]),
        (0xDC, 0x06): ([
            _wire_field(1, "offset", "u8", "Asset-tag byte offset 0..62"),
            _wire_field(2, "count", "u8", "Requested byte count 0..16; offset + count <= 63"),
        ], [
            _wire_field(1, "total_length", "u8", "Total stored asset-tag length"),
            _wire_field("2–end", "asset_tag", "up to count bytes", "Requested asset-tag slice"),
        ]),
        (0xDC, 0x08): ([
            _wire_field(1, "offset", "u8", "Asset-tag byte offset 0..62; writes must be contiguous"),
            _wire_field(2, "count", "u8", "Data byte count 0..16; offset + count <= 63"),
            _wire_field("3–end", "asset_tag", "count bytes", "Exactly count bytes written at offset"),
        ], [
            _wire_field(1, "total_length", "u8", "New stored asset-tag length"),
        ]),
    }
    for group, command, name, safety, runnable in (
        (0x52, 0x01, "Get Manager Certificate Fingerprint", "read-only", False),
        (0x52, 0x02, "Get Bootstrap Account Credentials", "sensitive", False),
        (0xDC, 0x07, "Get Sensor Information", "read-only", True),
        (0xDC, 0x10, "Get Temperature Readings", "read-only", True),
        (0xDC, 0x06, "Get Asset Tag", "read-only", True),
        (0xDC, 0x08, "Set Asset Tag", "state-changing", True),
    ):
        source = groups[(f"0x{group:02x}", f"0x{command:02x}")]
        length = source["request"]["length"]
        bounds = (length + 1, length + 1) if isinstance(length, int) else (3, 19)
        response_length = source["response"].get("length")
        response_bounds = ((response_length + 1, response_length + 1)
                           if isinstance(response_length, int) else {
                               (0x52, 0x01): (34, 34),
                               (0xDC, 0x07): (3, 19),
                               (0xDC, 0x10): (3, 19),
                               (0xDC, 0x06): (2, 18),
                           }[(group, command)])
        request_fields, response_fields = group_fields[(group, command)]
        rows.append(_manual_command(
            (0x2C, command, group), name=name, handler=source["handler"],
            purpose=source["effects"], privilege=source["privilege"],
            request_length=bounds, response_length=response_bounds,
            request_fields=[_wire_field(0, "group_id", "u8", f"fixed 0x{group:02x}"),
                            *request_fields],
            response_fields=[_wire_field(0, "group_id", "u8", f"echoed group identifier 0x{group:02x}"),
                             *response_fields],
            completion_codes=source["completion_codes"], activation=source["activation"],
            safety=safety, owner="DMTF/DCMI group handler",
            evidence=source.get("evidence", source.get("spec", "")), runnable=runnable,
        ))

    dcmi = groups[("0xdc", "0x01")]
    dcmi_parameters = {
        1: (7, (
            _wire_field(4, "reserved", "u8", "Reserved; zero"),
            _wire_field(5, "capabilities_1", "u8 bitfield", "bit0 power management; bits1:7 reserved"),
            _wire_field(6, "capabilities_2", "u8 bitfield", "bit0 in-band system interface; bit1 serial terminal mode; bit2 secondary LAN; bits3:7 reserved"),
        )),
        2: (9, (
            _wire_field("4–5", "sel_attributes", "u16le bitfield", "bits0:11 maximum SEL entries; bit12 reserved; bit13 record-level flush; bit14 entire-SEL flush; bit15 automatic rollover"),
            _wire_field("6–7", "reserved", "u16le", "Reserved; zero"),
            _wire_field(8, "temperature_sampling_frequency", "u8", "Temperature-monitoring sampling frequency from dcmi_cap.json"),
        )),
        3: (6, (
            _wire_field(4, "power_management_address", "u8 bitfield", "bits0:6 power-management device slave address; bit7 reserved"),
            _wire_field(5, "bmc_channel_revision", "u8 bitfield", "bits0:3 device revision; bits4:7 BMC channel number"),
        )),
        4: (7, (
            _wire_field(4, "mandatory_primary_lan", "u8", "Mandatory primary LAN out-of-band support"),
            _wire_field(5, "optional_secondary_lan", "u8", "Optional secondary LAN out-of-band support"),
            _wire_field(6, "optional_serial_mode", "u8", "Optional serial out-of-band terminal-mode capability"),
        )),
    }
    for selector, (response_length, parameter_fields) in dcmi_parameters.items():
        rows.append(_manual_command(
            (0x2C, 0x01, 0xDC, selector), name=f"Get DCMI Capabilities Parameter {selector}",
            handler=dcmi["handler"], purpose=f"{dcmi['effects']} Parameter selector {selector}.",
            privilege=dcmi["privilege"], request_length=(2, 2),
            response_length=(response_length, response_length),
            request_fields=[_wire_field(0, "group_id", "u8", "fixed 0xdc"),
                            _wire_field(1, "parameter_selector", "u8", f"fixed 0x{selector:02x}")],
            response_fields=[
                _wire_field(0, "group_id", "u8", "echoed group identifier 0xdc"),
                _wire_field(1, "conformance_major", "u8", "DCMI conformance major version"),
                _wire_field(2, "conformance_minor", "u8", "DCMI conformance minor version"),
                _wire_field(3, "parameter_revision", "u8", "Parameter revision"),
                *parameter_fields,
            ],
            completion_codes=dcmi["completion_codes"],
            activation=dcmi["activation"], safety="read-only", owner="DCMI group handler",
            evidence=dcmi["spec"],
        ))

    private = groups[("0x52", "0x03")]
    actions = {
        0x04: ("Read Host-Interface Settings", "read-only", "Reads the host-interface settings state byte.", 0xF4),
        0x05: ("Read Bootstrap Account File List", "sensitive", "Reads whether the bootstrap-account file list is present.", 0xF5),
        0x06: ("Private Maintenance No-op 06", "read-only", "Implemented switch slot with no operation; returns empty success.", None),
        0x07: ("Private Maintenance No-op 07", "read-only", "Implemented switch slot with no operation; returns empty success.", None),
        0x08: ("Private Maintenance No-op 08", "read-only", "Implemented switch slot with no operation; returns empty success.", None),
        0x09: ("Reinitialize Host-Interface State", "disruptive", "Reinitializes the DMTF host-interface state and returns its action marker.", 0xF9),
        0x0A: ("Private Maintenance No-op 0a", "read-only", "Implemented switch slot with no operation; returns empty success.", None),
        0x0B: ("Private Maintenance No-op 0b", "read-only", "Implemented switch slot with no operation; returns empty success.", None),
        0x0C: ("Clear Bootstrap Users", "destructive", "Clears bootstrap users and returns its action marker.", 0xFC),
    }
    for action, (name, safety, purpose, result) in actions.items():
        response_fields = [_wire_field(0, "group_id", "u8", "echoed group identifier 0x52")]
        if result is not None:
            response_fields.append(_wire_field(1, "action_result", "u8", f"fixed 0x{result:02x}"))
        rows.append(_manual_command(
            (0x2C, 0x03, 0x52, action), name=name, handler=private["handler"],
            purpose=purpose, privilege=private["privilege"],
            request_length=(2, 2), response_length=(len(response_fields), len(response_fields)),
            request_fields=[_wire_field(0, "group_id", "u8", "fixed 0x52"),
                            _wire_field(1, "action", "u8", f"fixed 0x{action:02x}")],
            response_fields=response_fields,
            completion_codes=private["completion_codes"],
            activation=private["activation"], safety=safety, owner="Supermicro private group handler",
            evidence=private["evidence"],
        ))
    return rows


def _cm_provision_commands() -> list[tuple[tuple[int, ...], dict]]:
    source = next(row for row in _PRIMARY["operations"] if row["handler"] == "OEMGetCMProvision")
    request_specs = {
        0x00: (2, 3, "Provision-state query/action; optional operand a accepts 1, 3, or 4; operand b is forbidden.", "state-changing", 1, 4, "Provision-state result varies by operand: one byte or big-endian u32; exact D-Bus method remains unresolved.", "136-237"),
        0x01: (2, 4, "Invokes doProvisioning; optional operands are ignored.", "state-changing", 1, 1, "u8 D-Bus boolean returned by doProvisioning.", "357-378"),
        0x02: (2, 4, "Reads getProvisioningTaskStatus as a D-Bus u32 and returns its low byte; optional operands are ignored.", "read-only", 1, 1, "u8 low byte of getProvisioningTaskStatus D-Bus u32.", "379-414"),
        0x03: (2, 4, "Returns the three-byte RoT CPLD version; optional operands are ignored.", "read-only", 3, 3, "bytes[3] raw RoT CPLD version.", "415-424"),
        0x05: (4, 4, "Invokes validateImage with operands a and b.", "state-changing", 1, 1, "u8 inverted D-Bus boolean returned by validateImage.", "427-461"),
        0x06: (4, 4, "Reads getFWInventory; operand a selects a result form and operand b is accepted.", "read-only", 0, None, "Response varies by operand: four version bytes, zero/three parsed bytes, or raw string bytes.", "462-608"),
        0x07: (3, 3, "Reads the indexed provisioning task status; operand a is 0..3.", "read-only", 2, 2, "u16be task status.", "609-675"),
        0x08: (4, 4, "Invokes getAntiRBID with operands a and b.", "state-changing", 2, 2, "u16be result returned by getAntiRBID.", "676-711"),
        0x09: (3, 4, "Reads a RoT CPLD register selected by operand a; operand b is ignored.", "sensitive", 1, 1, "u8 register value.", "712-723"),
        0x0A: (2, 4, "Returns constant 0x01; optional operands are ignored.", "read-only", 1, 1, "fixed u8 0x01.", "724-734"),
        0x0F: (3, 4, "Operand a=0 queries D-Boot status; a=1 dumps D-Boot using operand b and changes state.", "state-changing", 1, 1, "u8 D-Boot status/result.", "743-797"),
        0x20: (3, 3, "Invokes upBackupGoldenImage; operand a selects a supported field (0..5, 8, or 9); operand b is forbidden.", "state-changing", 1, 1, "u8 normalized D-Bus result for the selected upBackupGoldenImage field.", "830-911"),
        0x21: (3, 4, "Invokes eraseImage using operand a (0..5); operand b is ignored.", "destructive", 1, 1, "u8 security-state result returned by eraseImage.", "912-959"),
        0x30: (2, 4, "Aggregates getI2CMapProtection, getBmcConsoleLockout, getBmcJtagLockout, getAttestValidation, getROTState, and readCPLDFeatbit; optional operands are ignored.", "read-only", 1, 1, "u8 packed status bitfield; per-source bit positions remain unresolved.", "988-1075"),
        0x54: (2, 4, "Clears CMOS through CPLD control and logs the action; optional operands are ignored.", "destructive", 0, 0, "No response data.", "1146-1176"),
        0x55: (2, 4, "Cycles AC power through CPLD control and logs the action; optional operands are ignored.", "disruptive", 0, 0, "No response data.", "1177-1225"),
        0x84: (2, 4, "Reads the isOTP D-Bus boolean; optional operands are ignored.", "sensitive", 1, 1, "u8 boolean returned by isOTP.", "1318-1339"),
        0x85: (2, 4, "Invokes the clearRaProvision D-Bus action; optional operands are ignored.", "destructive", 1, 1, "u8 boolean returned by clearRaProvision.", "1340-1361"),
        0x86: (3, 3, "Reads OTP key material; operand a is required and operand b is forbidden.", "sensitive", 0, None, "Variable key bytes; exact string length depends on backend.", "1362-1392"),
        0x87: (2, 2, "Reads the OTP serial number; operands are forbidden.", "sensitive", 0, None, "Variable serial-number bytes.", "1393-1424"),
        0xDB: (2, 4, "Returns no data except when operand a=5, which returns a padded/truncated 256-byte file.", "sensitive", 0, 256, "Empty response or exactly 256 bytes for operand a=5.", "281-350"),
        0xFF: (2, 4, "Returns constant 0x03; optional operands are ignored.", "read-only", 1, 1, "fixed u8 0x03.", "281-290"),
    }
    names = {
        0x00: "Get Provision State", 0x01: "Run Provisioning", 0x02: "Get Provision Task Status Byte",
        0x03: "Get RoT CPLD Version", 0x05: "Validate Image", 0x06: "Get Firmware Inventory",
        0x07: "Get Provision Task Status by Index", 0x08: "Get Anti-RBID", 0x09: "Read RoT CPLD Register",
        0x0A: "Get Provision Capability", 0x0F: "Query or Dump D-Boot", 0x20: "Update Backup Golden Image",
        0x21: "Erase Image", 0x30: "Get Provision Summary", 0x54: "Clear CMOS",
        0x55: "Cycle AC Power", 0x84: "Check OTP State", 0x85: "Clear RA Provisioning",
        0x86: "Get OTP Key Material", 0x87: "Get OTP Serial Number", 0xDB: "Read Provision File",
        0xFF: "Get Provision Status Code",
    }
    rows = []
    for subcommand, (request_min, request_max, purpose, safety, response_min, response_max, response_meaning, lines) in request_specs.items():
        response_type = "u16be" if subcommand in (0x07, 0x08) else "u8"
        response_fields = [] if response_max == 0 else [
            _wire_field(0, "result", "see meaning" if response_max is None or response_min != response_max else "bytes[3]" if response_max == 3 else response_type, response_meaning)
        ]
        if subcommand in (0x03,):
            response_fields = [_wire_field(0, "rot_cpld_version", "bytes[3]", response_meaning)]
        if subcommand == 0x20:
            response_fields = [_wire_field(0, "security_status", "u8", response_meaning)]
        if subcommand == 0x30:
            response_fields = [_wire_field(0, "provision_status", "u8 bitfield", response_meaning)]
        if subcommand in (0x0A, 0xFF):
            response_fields = [_wire_field(0, "result", "u8", response_meaning)]
        request_fields = [
            _wire_field(0, "outer_selector", "u8", "fixed 0x28"),
            _wire_field(1, "provision_command", "u8", f"fixed 0x{subcommand:02x}"),
        ]
        if request_max > 2:
            a_type = "u8" if request_min >= 3 else "optional u8"
            request_fields.append(_wire_field(2, "operand_a", a_type, purpose))
        if request_max > 3:
            b_type = "u8" if request_min >= 4 else "optional u8"
            request_fields.append(_wire_field(3, "operand_b", b_type, purpose))
        row = _manual_command(
            (0x30, 0x51, 0x28, subcommand), name=names[subcommand], handler=source["handler"],
            purpose=purpose, privilege=source["privilege_name"],
            request_length=(request_min, request_max), response_length=(response_min, response_max),
            request_fields=request_fields, response_fields=response_fields,
            completion_codes=source["completion_codes"], activation=source["activation"],
            safety=safety, owner="Supermicro primary provisioning subprotocol",
            evidence=f"OEMGetCMProvision target decompilation lines {lines}; provider SHA-256 {X14_PRIMARY_PROVIDER_SHA256}",
        )
        row[1]["cm_subcommand"] = subcommand
        row[1]["validator"] = "x14-cm-provision"
        rows.append(row)
    return rows


SUPERMICRO_X14: dict[tuple[int, ...], dict] = {}
for _entry in _PRIMARY["registrations"]:
    _result = _primary_direct(_entry)
    if _result:
        SUPERMICRO_X14[_result[0]] = _result[1]
for _entry in _PRIMARY["operations"]:
    _key, _contract = _primary_operation(_entry)
    SUPERMICRO_X14[_key] = _contract
for _key, _contract in _cm_provision_commands():
    SUPERMICRO_X14[_key] = _contract
for _key, _contract in _auxiliary_commands():
    SUPERMICRO_X14[_key] = _contract
SUPERMICRO_X14[(0x2C, 0x08, 0xDC)]["validator"] = "x14-asset-tag"


def _codec_field(field: dict, *, constant: int | None = None) -> dict | None:
    kind = field["type"]
    if kind in {
        "u8", "bool8", "u8 boolean", "u8 bitfield", "u8 bitset",
        "packed channel/options u8", "packed selector/revision u8",
    }:
        result = {"name": field["name"], "kind": "u8"}
    elif kind in {"u16le", "u16le bitfield"}:
        result = {"name": field["name"], "kind": "u16le"}
    elif kind == "u16be":
        result = {"name": field["name"], "kind": "u16be"}
    elif kind == "u32le":
        result = {"name": field["name"], "kind": "u32le"}
    elif match := re.fullmatch(r"bytes\[(\d+)]", kind):
        result = {"name": field["name"], "kind": "bytes", "length": int(match.group(1))}
    else:
        return None
    if constant is not None:
        result["constant"] = constant
    return result


def _fixed_codec(name: str, fields: list[dict] | None, length: tuple[int | None, int | None], *, response: bool = False):
    if fields is None or length[0] is None or length[0] != length[1]:
        return None
    codec_fields = []
    if response:
        codec_fields.append({"name": "completion_code", "kind": "u8"})
    for field in fields:
        meaning = field.get("meaning", "")
        constant = (
            int(field["value"], 0) if isinstance(field.get("value"), str)
            else field.get("value") if isinstance(field.get("value"), int)
            else int(meaning.removeprefix("fixed "), 0) if meaning.startswith("fixed 0x")
            else None
        )
        codec = _codec_field(field, constant=constant)
        if codec is None:
            return None
        codec_fields.append(codec)
    return build_fixed_packet_class(name, codec_fields, require_fields=not response)


SUPERMICRO_X14_PAYLOADS = {}
for _key, _contract in SUPERMICRO_X14.items():
    _request = _fixed_codec(f"X14 {_contract['name']} Request", _contract["request_fields"], _contract["request_length"])
    _response = _fixed_codec(f"X14 {_contract['name']} Response", _contract["response_fields"], _contract["response_length"], response=True)
    if _request is not None or _response is not None:
        SUPERMICRO_X14_PAYLOADS[_key] = (_request, _response)


SUPERMICRO_X14_CMD_NAMES = {key: value["name"] for key, value in SUPERMICRO_X14.items()}
X14_REGISTRATIONS = tuple(
    {**entry, "provider": "libsupermicrooemcmds.so.0.0.1"}
    for entry in _PRIMARY["registrations"]
) + tuple(X14_CATALOG["auxiliary_registrations"])

register("supermicro-x14", None, SUPERMICRO_X14_CMD_NAMES, SUPERMICRO_X14_PAYLOADS)

__all__ = [
    "SUPERMICRO_X14", "SUPERMICRO_X14_CMD_NAMES", "SUPERMICRO_X14_PAYLOADS",
    "X14_CATALOG", "X14_REGISTRATIONS", "X14_FIRMWARE_SHA256", "X14_ROOTFS_SHA256",
    "X14_PRIMARY_PROVIDER_SHA256", "X14_PRIMARY_PROVIDER_BUILD_ID",
]
