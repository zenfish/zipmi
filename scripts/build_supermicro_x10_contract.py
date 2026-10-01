#!/usr/bin/env python3
# z-artifact: b16cf6c0-941c-4003-82d3-83b9431adc00
"""Build the pinned X10 contract from static-analysis census artifacts.

This is an analysis importer, not a normal build step.  Its two JSON inputs are
produced from the pinned ELF registration table and dispatcher disassembly.
Optional semantic overrides are keyed by ``netfn/cmd[/prefix...]``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / "zipmi/data/sources/supermicro-x10-contracts.json"
LIVE_EVIDENCE_PATH = ROOT / "docs/evidence/20261001T-supermicro-x10-safe-live-validation.json"
PARENTS = {"30/68", "30/70", "30/a0", "30/74", "30/48"}
STANDARD_OVERRIDES = {"06/43"}
REJECT_TARGETS = {"30/70": "0xf8fe4"}
A0_HANDLERS = {
    0x01: "GetUploadResvID", 0x02: "StartFileUpload", 0x03: "FileUpload",
    0x04: "ApplyFileCommand", 0x05: "PrepareFileDownload",
    0x06: "PrepareFileDownloadDone", 0x07: "FileDownload",
    0x08: "FileDownloadDone", 0x09: "GetBIOSSettingFileStatus",
    0x0A: "BIOSSettingDownload", 0x0B: "BIOSSettingDownloadDone",
    0x0C: "GetBIOSSettingUpdateStatus", 0x0D: "StartBIOSCurrentSettingUpload",
    0x0E: "BIOSCurrentSettingUpload", 0x0F: "BIOSCurrentSettingUploadDone",
    0x10: "GetBIOSCurrentSettingStatus", 0x11: "GetSetBiosOOBCapability",
    0x12: "GetSetBiosOOBIdentify", 0x13: "StartBIOSDATFileUpload",
    0x14: "BIOSDATFileUpload", 0x15: "BIOSDATFileUploadDone",
    0x17: "GetBIOSDATFileInfo", 0x18: "GetPowerStatus", 0x19: "GetDMIStatus",
    0x1A: "DMIDownload", 0x1B: "DMIDownloadDone", 0x1C: "GetOOBUpdateStatus",
    0x1D: "StartCurrentDMIUpload", 0x1E: "CurrentDMIUpload",
    0x1F: "CurrentDMIUploadDone", 0x20: "GetOOBFileStatus",
    0x21: "DataToBMCReadyNotify", 0x22: "DataToBIOSReadyNotify",
    0x23: "DataToBIOSDone", 0x24: "DataToBMCDone", 0x25: "GetOOBFileChecksum",
    0x26: "StartBIOSUploadToBMC", 0x27: "BIOSUploadToBMC",
    0x28: "BIOSUploadToBMCDone", 0x29: "GetBIOSFileSize",
    0x2A: "ClearBIOSUploadFile", 0x30: "BIOSDownloadFormBMC",
    0x31: "BIOSDownloadFormBMCDone", 0x32: "BiosSWHandShake",
    0x33: "TrigerBiosCfgService", 0xFF: "SetOOBDebugFlag",
}

BEHAVIOR_DELTAS = {
    "30/68/08": "X10 applies LDAP configuration and credentials; X14 returns a compatibility rejection.",
    "30/68/0b": "X10 sets, gets, deletes, and tests alert configuration; X14 returns a compatibility rejection.",
    "30/68/13": "X10 reaches BBP configuration and shell paths; X14 validates but does not persist BBP state.",
    "30/68/1c": "X10 persists syslog configuration; X14 retains a no-op compatibility leaf.",
    "30/68/1d": "X10 persists SEL forwarding state; X14 retains a no-op compatibility leaf.",
    "30/70/62": "X10 commits BBP timeout state and controls a timer; X14 is a success stub.",
    "30/70/63": "X10 commits link configuration; X14 validates the setter without writing it.",
    "30/70/64": "X10 commits AC power-on state; X14 validates the setter without writing it.",
    "30/70/b7": "X10 executes a shell command and rewrites five web-service settings; X14 only checks lockdown.",
    "30/70/b8": "X10 executes four shell commands; X14 is a no-op.",
    "30/70/ee": "X10 actively scans Broadcom storage; X14 stubs this leaf and exposes structured Broadcom queries.",
}
REPURPOSED_SAME_WIRE = {
    "30/68/1e", "30/70/b9", "30/70/fc",
    "30/a0/09", "30/a0/0a", "30/a0/0b", "30/a0/0c", "30/a0/0e",
    "30/a0/10", "30/a0/15", "30/a0/1a", "30/a0/2a",
}
TARGET_UNBOUNDED = {"30/23", "3a/3e"}
DIRECT_BOUNDS = {
    "2e/01": {"request": (0, None)},
    "2e/02": {"request": (0, None), "response": (0, None)},
    "2e/03": {"request": (0, 2), "response": (1, 1)},
    "2e/06": {"request": (0, None)},
    "2e/07": {"request": (0, None)},
    "2e/17": {"request": (0, None)},
    "2e/d9": {"request": (9, None), "response": (3, None)},
    "06/43": {"request": (3, 4), "response": (0, None)},
    "2c/16": {"response": (1, None)},
    "30/01": {"request": (0, None)},
    "30/23": {"request": (4, 4)},
    "30/2a": {"request": (0, 0)},
    "30/2c": {"request": (3, 4), "response": (0, 2)},
    "30/2d": {"request": (0, None), "response": (2, 12)},
    "30/30": {"request": (2, 2)},
    "30/31": {"request": (2, 2)},
    "30/40": {"request": (0, None)},
    "30/41": {"request": (0, 0)},
    "30/42": {"request": (0, None)},
    "30/44": {"request": (0, 0)},
    "30/45": {"request": (0, None), "response": (0, None)},
    "30/47": {"request": (1, None), "response": (0, None)},
    "30/48": {"request": (0, None)},
    "30/49": {"request": (1, None)},
    "30/4a": {"request": (1, None)},
    "30/60": {"request": (4, 4), "response": (0, None)},
    "30/61": {"request": (4, 4)},
    "30/62": {"request": (6, None)},
    "30/63": {"request": (6, 6)},
    "30/64": {"request": (2, 2)},
    "30/65": {"request": (2, 2)},
    "30/66": {"request": (2, 2)},
    "30/69": {"request": (12, 12)},
    "30/6a": {"request": (0, None), "response": (0, 1)},
    "30/6d": {"request": (0, None)},
    "30/6e": {"request": (0, None)},
    "30/6f": {"request": (4, 4)},
    "30/71": {"request": (0, None), "response": (0, 9)},
    "30/72": {"request": (1, 2), "response": (0, 1)},
    "30/73": {"request": (1, 2), "response": (0, 1)},
    "30/74": {"request": (0, None), "response": (0, 1)},
    "30/90": {"request": (4, None), "response": (0, None)},
    "30/91": {"request": (4, None)},
    "30/92": {"request": (0, None)},
    "30/93": {"request": (0, None), "response": (1, 4)},
    "30/94": {"request": (0, None), "response": (1, 64)},
    "30/95": {"request": (0, None)},
    "30/96": {"request": (0, None)},
    "30/97": {"request": (0, None)},
    "30/98": {"request": (0, None)},
    "30/99": {"request": (10, 10)},
    "30/9a": {"request": (0, None)},
    "30/9b": {"request": (0, None)},
    "30/9d": {"request": (0, None)},
    "30/9e": {"request": (0, None)},
    "30/9f": {"request": (0, None)},
    "30/a1": {"request": (0, None)},
    "30/ac": {"request": (1, 18), "response": (8, 16)},
    "30/b0": {"request": (0, None)},
    "30/e2": {"request": (0, None)},
    "30/e3": {"request": (0, None)},
    "30/e6": {"request": (0, None)},
    "30/e7": {"request": (0, None)},
    "3a/3e": {"request": (1, 1)},
    "3a/3f": {"request": (12, 12)},
    "3c/03": {"request": (0, 0)},
    "3c/04": {"request": (8, 8)},
    "3c/08": {"request": (3, 3)},
    "3c/09": {"request": (2, 2)},
    "3c/40": {"request": (0, None)},
    "3c/41": {"request": (0, 0)},
}


def _humanize(name: str) -> str:
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name).replace("_", " ")
    return re.sub(r"\s+", " ", words).strip()


def _safety(handler: str) -> tuple[str, str]:
    text = handler.lower()
    if any(word in text for word in ("factory", "flashfw", "restorefru", "restoresdr", "clearbios")):
        return "destructive", "Persistent data, firmware, or configuration can be erased or replaced."
    if any(word in text for word in ("reset", "powerstatechange", "finalizefw", "triggerpower")):
        return "disruptive", "May reset a controller, service, or host-visible subsystem."
    if any(word in text for word in ("productionkey", "rakp", "password", "license", "debugflag")):
        return "sensitive", "Reads or changes authentication, licensing, or diagnostic-security state."
    read_prefixes = ("get", "read", "check", "is", "detect")
    if text.startswith(read_prefixes) and not text.startswith(("getset", "get_set")):
        return "read-only", "Handler name and recovered call graph contain no state-changing verb."
    return "state-changing", "Handler accepts a setter/action path; named execution requires --unsafe."


def _layout(*, selector: int | None, response: bool = False) -> dict:
    fields = [] if response else ([{
        "offset": 0, "name": "selector", "type": "u8",
        "meaning": "nested operation selector", "value": f"0x{selector:02x}",
    }] if selector is not None else [])
    return {
        "minimum_bytes": 0 if response else (1 if selector is not None else 0),
        "maximum_bytes": None,
        "fields": fields,
        "status": "partial pending handler-specific override",
    }


def _length_bounds(value: object, explicit: tuple[int | None, int | None] | None,
                   identity: str, direction: str) -> tuple[int | None, int | None]:
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0:
            raise ValueError(f"negative {direction} length for {identity}")
        return value, value
    if explicit is None:
        raise ValueError(f"textual {direction} rule for {identity} needs explicit bounds: {value!r}")
    low, high = explicit
    if any(bound is not None and (isinstance(bound, bool) or not isinstance(bound, int) or bound < 0)
           for bound in explicit):
        raise ValueError(f"invalid {direction} bounds for {identity}: {explicit}")
    if low is not None and high is not None and low > high:
        raise ValueError(f"inverted {direction} bounds for {identity}: {explicit}")
    return low, high


def _contract_fields(values: list[str], *, selector: int | None = None) -> list[dict]:
    fields = []
    if selector is not None:
        fields.append({
            "offset": 0, "name": "selector", "type": "u8",
            "meaning": "nested operation selector", "value": f"0x{selector:02x}",
        })
    for index, meaning in enumerate(values):
        fields.append({
            "offset": "see meaning", "name": f"recovered_field_{index + 1}",
            "type": "bytes (width described in meaning)", "meaning": meaning,
        })
    return fields


def _direct_semantics(registration: dict) -> dict:
    contract = registration.get("analysis", {}).get("contract")
    if not contract:
        return {}
    if "request" in contract:
        request_rule = contract["request"]["length"]
        request_fields = contract["request"].get("fields", [])
        response_rule = contract["response"]["payload_length"]
        response_fields = contract["response"].get("fields", [])
        uncertainty = contract.get("uncertainty")
    else:
        request_rule = contract["request_admission"]
        request_fields = ([contract.get("fields", {}).get("request")]
                          if contract.get("fields", {}).get("request") else [])
        response_rule = contract["success_response"]["payload_length"]
        response_fields = ([contract.get("fields", {}).get("response")]
                           if contract.get("fields", {}).get("response") else [])
        uncertainty = "; ".join(contract.get("uncertain", ()))
    identity = registration["wire_key"].lower()
    explicit = DIRECT_BOUNDS.get(identity, {})
    req_low, req_high = _length_bounds(request_rule, explicit.get("request"), identity, "request")
    rsp_low, rsp_high = _length_bounds(response_rule, explicit.get("response"), identity, "response")
    safety_text = contract["safety"].lower()
    side_effects = contract["side_effects"]
    if isinstance(side_effects, list):
        side_effects = "; ".join(side_effects)
    safety = (
        "read-only" if safety_text == "read-only" or safety_text.endswith(" read")
        else "destructive" if "destructive" in safety_text or "firmware" in side_effects.lower()
        else "disruptive" if any(word in safety_text for word in ("disruptive", "reset", "power"))
        else "sensitive" if any(word in safety_text for word in ("sensitive", "credential"))
        else "state-changing"
    )
    uncertainty = uncertainty or "No unresolved target behavior."
    completion_codes = contract["completion_codes"]
    if isinstance(completion_codes, dict):
        completion_codes = [f"{code} {meaning}" for code, meaning in completion_codes.items()]
    name = contract.get("name", registration["handler"]["symbol"])
    return {
        "name": name, "handler": name,
        "purpose": f"{_humanize(name)}. {side_effects}",
        "request": {
            "minimum_bytes": req_low, "maximum_bytes": req_high,
            "fields": _contract_fields(request_fields),
            "status": "complete static contract; undefined target behavior is stated explicitly",
            "length_rule": request_rule,
        },
        "response": {
            "minimum_bytes": rsp_low, "maximum_bytes": rsp_high,
            "fields": _contract_fields(response_fields),
            "status": "complete static contract; undefined target behavior is stated explicitly",
            "length_rule": response_rule,
        },
        "completion_codes": completion_codes,
        "side_effects": side_effects, "safety": safety,
        "safety_note": f"{side_effects} Static boundary: {uncertainty}",
        "confidence": contract["confidence"],
        "evidence": f"{contract.get('evidence', registration['analysis'].get('source_fragment', 'pinned handler disassembly'))}; {uncertainty}",
    }


def _base_operation(*, netfn: int, command: int, handler: str, privilege: str,
                    prefix: list[int], evidence: str) -> dict:
    safety, note = _safety(handler)
    selector = prefix[0] if prefix else None
    return {
        "netfn": f"0x{netfn:02x}", "command": f"0x{command:02x}", "prefix": prefix,
        "selector_offset": 0 if prefix else None,
        "name": handler, "handler": handler,
        "purpose": _humanize(handler), "privilege": privilege,
        "request": _layout(selector=selector), "response": _layout(selector=None, response=True),
        "completion_codes": ["0x00 success", "0xCC invalid field or unsupported operation"],
        "activation": "unconditional firmware registration",
        "side_effects": note, "safety": safety, "safety_note": note,
        "confidence": "exact wire identity and handler boundary; semantic detail supplied by target-body override",
        "evidence": evidence, "runnable": True, "live": None,
    }


def _merge(row: dict, override: dict) -> dict:
    for key, value in override.items():
        if key in {"request", "response"}:
            row[key].update(value)
        else:
            row[key] = value
    return row


def _load_semantics(paths: list[Path] | None) -> dict[str, dict]:
    if not paths:
        return {}
    normalized = {}
    def bound(value: object) -> int | None:
        return value if isinstance(value, int) else None

    def fields(values: object) -> list[dict]:
        return [
            {
                **field,
                "meaning": field.get("meaning", field.get("value", "Recovered wire field.")),
            }
            for field in (values or [])
        ]

    rows = {}
    for path in paths:
        raw = json.loads(path.read_text())
        for identity, source in raw.get("operations", raw).items():
            if identity.lower() in rows:
                raise ValueError(f"duplicate semantic override: {identity}")
            rows[identity.lower()] = source

    for identity, source in rows.items():
        request, response = source.get("request", {}), source.get("response", {})
        safety_value = source.get("safety", "unsafe-until-callee-proven-read-only").lower()
        safety = source.get("safety_class")
        if safety not in {"read-only", "sensitive", "state-changing", "disruptive", "destructive"}:
            if safety_value.startswith("read-only") or safety_value in {"raw-hardware read candidate"}:
                safety = "read-only"
            elif "destructive" in safety_value:
                safety = "destructive"
            elif any(word in safety_value for word in ("reset", "power state", "disruptive", "unmount")):
                safety = "disruptive"
            elif any(word in safety_value for word in ("credential", "disclosure", "sensitive")):
                safety = "sensitive"
            else:
                safety = "state-changing"
        side_effects = source.get("side_effects", [])
        if isinstance(side_effects, list):
            side_effects = "; ".join(side_effects) or "No mutation sink observed."
        completion = source.get("completion_codes", [])
        if isinstance(completion, dict):
            completion = [f"{code} {meaning}" for code, meaning in completion.items()]
        normalized[identity.lower()] = {
            "name": source.get("name", source["handler"]), "handler": source["handler"],
            "purpose": source["purpose"],
            "request": {
                "minimum_bytes": bound(request.get("minimum_bytes", request.get("min_bytes_including_selector"))),
                "maximum_bytes": bound(request.get("maximum_bytes", request.get("max_bytes_including_selector"))),
                "fields": fields(request.get("fields")),
                "status": request.get("status", request.get("layout_status", "partial")),
            },
            "response": {
                "minimum_bytes": bound(response.get("minimum_bytes", response.get("min_bytes_excluding_completion"))),
                "maximum_bytes": bound(response.get("maximum_bytes", response.get("max_bytes_excluding_completion"))),
                "fields": fields(response.get("fields")),
                "status": response.get("status", response.get("layout_status", "partial")),
            },
            "completion_codes": completion, "side_effects": side_effects,
            "safety": safety, "safety_note": source.get("note", side_effects),
            "confidence": source["confidence"],
            "evidence": json.dumps(source["evidence"], sort_keys=True),
            "genealogy_match_proven": source.get("genealogy_match_proven", True),
        }
    return normalized


def _identity(row: dict) -> str:
    parts = [int(row["netfn"], 0), int(row["command"], 0), *row.get("prefix", ())]
    return "/".join(f"{part:02x}" for part in parts)


def _attach_live_evidence(operations: list[dict]) -> dict:
    evidence = json.loads(LIVE_EVIDENCE_PATH.read_text())
    for probe in evidence["probes"]:
        netfn, command = int(probe["netfn"], 0), int(probe["command"], 0)
        request = bytes.fromhex(probe["request"])
        matches = [
            row for row in operations
            if int(row["netfn"], 0) == netfn
            and int(row["command"], 0) == command
            and request.startswith(bytes(row.get("prefix", ())))
        ]
        if matches:
            longest = max(len(row.get("prefix", ())) for row in matches)
            matches = [row for row in matches if len(row.get("prefix", ())) == longest]
        if len(matches) != 1:
            raise ValueError(f"live probe does not identify one operation: {probe}")
        response = probe["response"] or "empty response"
        matches[0]["live"] = (
            f"zBMC run {evidence['run_id']}; CC {probe['completion_code']}; "
            f"response {response}; {LIVE_EVIDENCE_PATH.relative_to(ROOT)}"
        )
    return evidence


def _genealogy(operations: list[dict]) -> list[dict]:
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    x10 = {_identity(row): row for row in operations}
    x14 = {"/".join(f"{part:02x}" for part in key): row for key, row in SUPERMICRO_X14.items()}
    rows = [{
        "lineage_id": "file-oob-parent-a0",
        "canonical_action": "File and out-of-band operation parent dispatcher",
        "x10": "30/a0 FileTransactions; 46 accepted selectors",
        "x14": "30/a0 OOBHandler; 27 accepted selectors",
        "relation": "repurposed",
        "risk_delta": "Same parent wire address, different dispatcher and selector surface; never infer compatibility from 30/a0 alone.",
        "evidence": "Pinned X10 FileTransactions switch and pinned X14 OOBHandler contract.",
    }]
    consumed_x14 = set()
    for identity, old in sorted(x10.items()):
        same_wire = x14.get(identity)
        moved_identity = next((
            candidate for candidate, row in x14.items()
            if candidate not in consumed_x14 and row["handler"] == old["handler"]
        ), None)
        new_identity = identity if same_wire is not None else moved_identity
        new = x14.get(new_identity) if new_identity else None
        if new:
            consumed_x14.add(new_identity)
            old_name, new_name = old["handler"], new["handler"]
            if identity in BEHAVIOR_DELTAS:
                relation = "behavior-changed"
                risk = BEHAVIOR_DELTAS[identity] + " This is an attack-surface reduction where X14 removed mutation or shell sinks."
            elif identity in REPURPOSED_SAME_WIRE:
                relation = "repurposed"
                risk = "The generations assign different handlers to the same wire identity; payload compatibility must not be assumed."
            elif not old.get("genealogy_match_proven", True):
                relation = "uncertain"
                risk = "Same-wire X14 handler name is only a genealogy candidate; X10 inline behavior has not established semantic inheritance."
            elif old_name == new_name and identity == new_identity:
                relation = "retained"
                risk = "Wire identity and semantic handler family are retained; per-generation byte contracts still apply."
            else:
                relation = "renamed-reframed"
                risk = "The semantic handler survives under a renamed wrapper, changed identity, or changed decomposition; byte-level compatibility is not assumed."
            canonical = _humanize(new_name if relation == "renamed-reframed" else old_name)
            x10_text = f"{identity} {old_name}"
            x14_text = f"{new_identity} {new_name}"
            evidence = f"X10: {old['evidence']}; X14: {new['evidence']}"
        else:
            relation = "x10-only-dropped"
            canonical = _humanize(old["handler"])
            x10_text, x14_text = f"{identity} {old['handler']}", "No matching X14 OEM-IPMI operation"
            risk = "Removed from the X14 OEM-IPMI surface at this identity; alternate Redfish/D-Bus replacement is not claimed without evidence."
            evidence = old["evidence"]
        rows.append({
            "lineage_id": identity.replace("/", "-"), "canonical_action": canonical,
            "x10": x10_text, "x14": x14_text, "relation": relation,
            "risk_delta": risk, "evidence": evidence,
        })
    for identity, new in sorted(x14.items()):
        if identity in consumed_x14:
            continue
        rows.append({
            "lineage_id": f"x14-{identity.replace('/', '-')}",
            "canonical_action": _humanize(new["handler"]),
            "x10": "No matching X10 OEM-IPMI operation",
            "x14": f"{identity} {new['handler']}", "relation": "x14-new",
            "risk_delta": "New X14 OEM-IPMI exposure; assess its D-Bus, file, hardware, or provisioning backend independently.",
            "evidence": new["evidence"],
        })
    return rows


def _selector_metadata(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    result = {}
    for family in json.loads(path.read_text())["families"]:
        for row in family["rows"]:
            key = f"{int(family['netfn'], 0):02x}/{int(family['command'], 0):02x}/{int(row['selector'], 0):02x}"
            result[key] = row
    return result


def _nested_semantics(identity: str, handler: str, metadata: dict) -> dict:
    if not metadata:
        return {"handler": handler, "name": handler}
    generic = handler.startswith("OEMCommandSet_70:inline@")
    calls = [call.removesuffix(".isra.19").removesuffix(".isra.42").removesuffix(".isra.43")
             for call in metadata.get("calls", ())]
    uninformative = {"memset", "memcpy", "open", "close", "unlink", "ioctl", "mmap", "run_shellcmd"}
    named_calls = [call for call in calls if call not in uninformative]
    if not generic:
        name, match_proven = handler.removesuffix("_inline"), True
    elif named_calls:
        name, match_proven = named_calls[0], True
    elif metadata.get("x14_same_wire_handler"):
        name, match_proven = metadata["x14_same_wire_handler"], False
    else:
        name, match_proven = f"X10Inline70_{identity.rsplit('/', 1)[1].upper()}", False
    read_only = metadata.get("recommended_gate") == "read-only-candidate"
    tags = metadata.get("risk_tags", ())
    sinks = metadata.get("sink_calls", ())
    purpose = _humanize(name)
    if calls:
        purpose += f"; target calls {', '.join(calls)}"
    if metadata.get("secondary_dispatch"):
        secondary = metadata["secondary_dispatch"]
        purpose += f"; secondary dispatch: {secondary.get('meaning', json.dumps(secondary, sort_keys=True))}"
    side_effects = (
        "Static call graph proves a query path; no mutation sink was found."
        if read_only else
        f"Unsafe path; target risk tags: {', '.join(tags) or 'state change not excluded'}"
        + (f"; sink calls: {', '.join(sinks)}" if sinks else "")
    )
    return {
        "handler": name, "name": name, "purpose": purpose,
        "safety": "read-only" if read_only else "state-changing",
        "safety_note": side_effects, "side_effects": side_effects,
        "confidence": "exact selector target and target call graph from pinned provider",
        "genealogy_match_proven": match_proven,
    }


def build(registrations_path: Path, dispatch_path: Path, semantics_paths: list[Path] | None,
          selector_census_path: Path | None = None) -> dict:
    source = json.loads(registrations_path.read_text())
    dispatch = json.loads(dispatch_path.read_text())
    semantics = _load_semantics(semantics_paths)
    selector_metadata = _selector_metadata(selector_census_path)
    registrations = source.get("registrations", source.get("rows"))
    operations = []

    for registration in registrations:
        wire = registration["wire_key"]
        if wire in PARENTS or wire in STANDARD_OVERRIDES:
            continue
        netfn, command = (int(value, 16) for value in wire.split("/"))
        handler = registration["handler"]["symbol"]
        operation = _base_operation(
            netfn=netfn, command=command, handler=handler,
            privilege=registration["privilege"]["name"], prefix=[],
            evidence=(f"OEMCmdTable row {registration['row_address']}; handler "
                      f"{registration['handler']['address']}; relocation "
                      f"{registration['evidence']['address']}"),
        )
        operation = _merge(operation, _direct_semantics(registration))
        operations.append(_merge(operation, semantics.get(_identity(operation), {})))

    for family in dispatch["families"]:
        wire = family["wire_key"]
        netfn, command = int(family["netfn"], 0), int(family["command"], 0)
        for child in family["selectors"]:
            selector = child["selector_value"]
            if child["case_target_address"] == REJECT_TARGETS.get(wire):
                continue
            if wire == "30/a0" and selector not in A0_HANDLERS:
                continue
            handler = A0_HANDLERS.get(selector) if wire == "30/a0" else f"{family['handler']['symbol']}_{selector:02X}"
            operation = _base_operation(
                netfn=netfn, command=command, handler=handler,
                privilege=family["privilege"]["name"], prefix=[selector],
                evidence=(f"{family['handler']['symbol']} {family['handler']['address']}; "
                          f"case {child['case_target_address']}; dispatch branch "
                          f"{child['evidence']['address']}"),
            )
            identity = _identity(operation)
            operation = _merge(operation, _nested_semantics(
                identity, selector_metadata.get(identity, {}).get("handler", handler),
                selector_metadata.get(identity, {}),
            ))
            operations.append(_merge(operation, semantics.get(identity, {})))

    expected = set(semantics)
    actual = {_identity(row) for row in operations}
    if missing := expected - actual:
        raise ValueError(f"semantic overrides do not match recovered operations: {sorted(missing)}")
    if duplicate := len(actual) != len(operations):
        raise ValueError(f"duplicate operation identities: {duplicate}")

    for operation in operations:
        operation["target_bounded"] = _identity(operation) not in TARGET_UNBOUNDED
    live_evidence = _attach_live_evidence(operations)

    genealogy = _genealogy(operations)
    return {
        "schema": "zipmi-supermicro-x10-contract-v1",
        "analysis_date": "2026-10-01",
        "firmware": {
            "image": source["source"]["firmware"],
            "image_sha256": source["source"]["flash_sha256"],
            "rootfs_sha256": "f414a4dc447a4bea09374398f47caca0112a35cd5f61030f19712634659c67fd",
            "provider_path": source["source"]["embedded_path"],
            "provider_sha256": source["source"]["sha256"],
        },
        "closure": {
            "registration_rows": len(registrations),
            "unique_wire_registrations": len({row["wire_key"] for row in registrations}),
            "operation_rows": len(operations),
            "rejected_selector_target": REJECT_TARGETS,
            "live_evidence": (
                f"Cold-boot zBMC run {live_evidence['run_id']} captured eight exact read-only named routes; "
                "no mutating request was sent and the guest was stopped afterward."
            ),
        },
        "registrations": registrations,
        "operations": sorted(
            operations,
            key=lambda row: (int(row["netfn"], 0), int(row["command"], 0), row["prefix"]),
        ),
        "genealogy": genealogy,
        "sources": [
            {"kind": "registration census", "sha256": hashlib.sha256(registrations_path.read_bytes()).hexdigest()},
            {"kind": "dispatcher census", "sha256": hashlib.sha256(dispatch_path.read_bytes()).hexdigest()},
            *[
                {"kind": "handler semantic contracts", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in (semantics_paths or [])
            ],
            {"kind": "safe live validation", "sha256": hashlib.sha256(LIVE_EVIDENCE_PATH.read_bytes()).hexdigest()},
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("registrations", type=Path)
    parser.add_argument("dispatch", type=Path)
    parser.add_argument("--semantics", type=Path, action="append")
    parser.add_argument("--selector-census", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    catalog = build(args.registrations, args.dispatch, args.semantics, args.selector_census)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"wrote {args.output}: {len(catalog['registrations'])} registrations, "
          f"{len(catalog['operations'])} operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
