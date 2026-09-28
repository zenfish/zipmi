# z-artifact: 51e82f4f-64f9-4c7c-a035-428e9f367948
"""IEIT NF5468M6 BMC 7.26.05 firmware-bound OEM registration catalog.

This target is AMI MegaRAC SP-X plus IEIT platform libraries, not the unrelated
OpenBMC ``inspur-ipmi-oem`` provider.  The packaged dispatch ledger is generated
directly from the pinned firmware's ELF registration tables.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ._registry import register


IEIT_FIRMWARE_SHA256 = "b7915aa4be2661d47d78cca6265dc11d8d06c23cc199e0ff80a2adc3ccd7c7d1"
IEIT_PDK_SHA256 = "250ccbd0943a4a5d07f679c99254fb7677b91efb526530df609aab995a27c2ab"
_SOURCE = Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-dispatch.json"
_PLATFORM_SOURCE = (
    Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-netfn30-34-38.json"
)
_PDK_SOURCE = Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-pdk-contracts.json"
_AUX_SOURCE = Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-aux-contracts.json"
_AMI_SOURCE = (
    Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-ami-netfn32-contracts.json"
)
_CATALOG = json.loads(_SOURCE.read_text())
_PLATFORM_CATALOG = json.loads(_PLATFORM_SOURCE.read_text())
_PDK_CATALOG = json.loads(_PDK_SOURCE.read_text())
_AUX_CATALOG = json.loads(_AUX_SOURCE.read_text())
_AMI_CATALOG = json.loads(_AMI_SOURCE.read_text())

if _CATALOG["firmware_sha256"] != IEIT_FIRMWARE_SHA256:
    raise RuntimeError("IEIT dispatch source does not match the pinned firmware")

IEIT_REGISTRATIONS: tuple[dict, ...] = tuple(_CATALOG["rows"])
_BY_ADDRESS: dict[tuple[int, int], list[dict]] = defaultdict(list)
for _registration in IEIT_REGISTRATIONS:
    _BY_ADDRESS[(_registration["netfn"], _registration["cmd"])].append(_registration)


def _contract(registrations: list[dict]) -> dict:
    handlers = [registration["handler"] for registration in registrations]
    lengths = {registration["declared_request_length"] for registration in registrations}
    exact = lengths.pop() if len(lengths) == 1 else None
    privilege = " / ".join(dict.fromkeys(
        registration["privilege"] for registration in registrations
    ))
    return {
        "name": " / ".join(handlers),
        "privilege": privilege,
        "purpose": "Firmware registration for " + " / ".join(handlers) + ".",
        "request": (
            f"Exactly {exact} payload bytes per dispatcher registration."
            if exact is not None else "Variable-length payload; handler contract required."
        ),
        "response": "Handler-specific response.",
        "request_length": (exact, exact) if exact is not None else (None, None),
        "request_fields": [],
        "response_fields": [],
        "completion_codes": [],
        "activation": "Statically registered in the pinned firmware.",
        "side_effects": "Not inferred from the handler name.",
        "safety": "unknown",
        "confidence": "Registration high; payload semantics not supplied by the dispatch table.",
        "registrations": registrations,
    }


IEIT_COMMANDS: dict[tuple[int, ...], dict] = {
    address: _contract(registrations)
    for address, registrations in sorted(_BY_ADDRESS.items())
}


def _update(address: tuple[int, int], **contract) -> None:
    IEIT_COMMANDS[address].update(contract)


def _leaf(address: tuple[int, int], prefix: bytes, **contract) -> None:
    base = IEIT_COMMANDS[address]
    IEIT_COMMANDS[(*address, *prefix)] = {
        **base, "prefix": prefix, "selector": prefix, **contract,
    }


def _json_summary(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _operation_bounds(operation: dict) -> tuple[int | None, int | None]:
    """Return only bounds proved by the normalized PDK contract."""
    request = operation["request"]
    length = request.get("length")
    if isinstance(length, int):
        bounds = (length, length)
    elif length == "2 or 3":
        bounds = (2, 3)
    elif isinstance(length, str) and length.startswith("at least 32"):
        bounds = (32, None)
    elif isinstance(length, str) and length.startswith("binary only ensures len<=3"):
        bounds = (0, 3)
    elif isinstance(length, str) and length[:1].isdigit():
        bounds = (int(length.split()[0].split("+")[0]), None)
    elif isinstance(request.get("minimum_length"), int):
        bounds = (request["minimum_length"], None)
    elif isinstance(request.get("minimum_length"), str):
        bounds = (int(request["minimum_length"].split()[1]), None)
    else:
        policy = request.get("registration_policy", {})
        bounds = ((policy["length"],) * 2
                  if policy.get("kind") == "exact" else (None, None))
    prefix_length = len(operation.get("auto_prefix", ()))
    if prefix_length and (bounds[0] is None or bounds[0] < prefix_length):
        bounds = (prefix_length, bounds[1])
    return bounds


def _pdk_contract(registration: dict, operation: dict) -> dict:
    top = registration["reviewed_top_level_contract"]
    source_safety = operation["safety"]["class"]
    safety = "sensitive" if source_safety == "sensitive-read-or-write" else source_safety
    confidence = operation["confidence"]
    prefix = bytes(int(value, 0) for value in operation.get("auto_prefix", ()))
    selector = (bytes([int(operation["selector_hex"], 0)])
                if operation.get("selector_hex") is not None else b"")
    return {
        **_contract(_BY_ADDRESS[(int(operation["netfn"], 0), int(operation["cmd"], 0))]),
        "name": operation["identity"],
        "purpose": operation["identity"] + ".",
        "privilege": {2: "User", 3: "Operator", 4: "Administrator"}.get(
            operation["privilege"], str(operation["privilege"])),
        "request": _json_summary(operation["request"]),
        "response": _json_summary(operation["response"]),
        "request_length": _operation_bounds(operation),
        "completion_codes": [
            f"{code} {meaning}" for code, meaning in top["completion_codes"].items()
        ],
        "activation": "Statically registered by the pinned IEIT PDK provider.",
        "side_effects": (
            "None identified; read-only handler."
            if safety == "read-only" else
            f"Firmware classifies this operation as {source_safety}; review its request contract before sending."
        ),
        "safety": safety,
        "confidence": confidence,
        "request_status": (
            "Complete" if confidence == "reviewed-binary-exact"
            else "Unknown" if confidence.startswith("unresolved") else "Partial"
        ),
        "response_status": (
            "Complete" if confidence == "reviewed-binary-exact"
            else "Unknown" if confidence.startswith("unresolved") else "Partial"
        ),
        "prefix": prefix,
        "selector": selector,
        "route_identity": prefix or selector,
        "selector_offset": operation.get("selector_offset"),
        "operation_id": operation["operation_id"],
        "source_contract": operation,
    }


def _aux_bounds(request: dict) -> tuple[int | None, int | None]:
    length = request.get("length")
    if isinstance(length, int):
        return length, length
    if isinstance(length, dict):
        high = length.get("maximum")
        return length.get("minimum"), high if isinstance(high, int) else None
    if request.get("unit_size"):
        return request["unit_size"] * request.get("minimum_units", 1), None
    return None, None


def _aux_contract(source: dict) -> dict:
    address = (int(source["netfn"], 0), int(source["command"], 0))
    safe = source["id"] in {
        "intel-pnm-platform-power-characterization-notification",
        "ami-hpm-increase-payload-size",
    }
    errors = source["response"].get("errors", ())
    return {
        **_contract(_BY_ADDRESS[address]),
        "name": source["name"],
        "purpose": source["name"] + ".",
        "privilege": source["privilege"]["name"].title(),
        "request": _json_summary(source["request"]),
        "response": _json_summary(source["response"]),
        "request_length": _aux_bounds(source["request"]),
        "request_fields": [],
        "response_fields": [],
        "completion_codes": [
            f"{error['completion_code']} {error['condition']}" for error in errors
        ],
        "activation": source["registration"]["activation"],
        "side_effects": "; ".join(source.get("effects", ())) or "None.",
        "safety": "read-only" if safe else "sensitive",
        "confidence": "high binary-reviewed auxiliary contract",
        "request_status": "Complete",
        "response_status": "Complete",
        "prefix": b"",
        "selector": b"",
        "route_identity": b"",
        "validator": {
            "ieit-chassis-identify": "chassis-identify",
            "intel-pnm-get-reading": "pnm-reading",
            "intel-pnm-power-state-change": "pnm-power-state",
        }.get(source["id"]),
        "source_contract": source,
    }


def _ami_contract(registration: dict, operation: dict) -> dict:
    address = (registration["netfn"], registration["cmd"])
    prefix = bytes.fromhex(operation["auto_prefix"] or "")
    selector = bytes.fromhex(operation["selector_hex"] or "")
    effect = {
        "safe": "read-only",
        "mutates": "state-changing",
        "security-sensitive": "sensitive",
        "destructive": "destructive",
    }[operation["effect"]]
    request = operation["request"]
    response = operation["response"]
    raw = operation["contract_kind"] == "raw-exact"
    return {
        **_contract(_BY_ADDRESS[address]),
        "name": operation["name"],
        "purpose": operation["side_effects"],
        "privilege": registration["privilege"],
        "request": _json_summary(request),
        "response": _json_summary(response),
        "request_length": (request["min_bytes"], request["max_bytes"]),
        "response_length_text": (
            f"Exactly {response['exact_bytes']} bytes including completion code"
            if response["exact_bytes"] is not None else
            f"{response['min_bytes']}–{response['max_bytes']} bytes including completion code"
        ),
        "completion_codes": [f"0x{code}" for code in operation["completion_codes"]],
        "activation": registration["activation"],
        "side_effects": operation["side_effects"],
        "safety": effect,
        "confidence": operation["confidence"],
        "request_status": "Complete",
        "response_status": "Partial" if raw else "Complete",
        "prefix": prefix,
        "selector": selector,
        "route_identity": prefix or selector,
        "selector_offset": operation["selector_offset"],
        "operation_id": operation["operation_id"],
        "source_contract": operation,
    }


_update(
    (0x30, 0x01),
    purpose="Return the rollback-flash status byte (this build always returns zero).",
    request="No request data.", response="One status byte, fixed to 0x00 in this build.",
    request_length=(0, 0), safety="read-only", side_effects="None.", confidence="high",
)
_update(
    (0x30, 0xA2),
    purpose="Enable, disable, or query protocol 0x1e using an ASCII control token.",
    request="Exactly one 10-byte ASCII token: 00SECURITY, 11SECURITY, or ??SECURITY.",
    response="Set: no data. Query: two duplicate ASCII state bytes (00 or 11).",
    request_length=(10, 10), safety="sensitive",
    side_effects="Enable/disable changes the BMC protocol policy.", confidence="high",
)
for _token, _operation, _safety, _effect in (
    (b"00SECURITY", "Disable protocol 0x1e", "state-changing", "Disables protocol 0x1e."),
    (b"11SECURITY", "Enable protocol 0x1e", "state-changing", "Enables protocol 0x1e."),
    (b"??SECURITY", "Query protocol 0x1e", "read-only", "None."),
):
    _leaf(
        (0x30, 0xA2), _token, name=f"Chip security: {_operation}", purpose=_operation + ".",
        request=f"Fixed ASCII token {_token.decode()} (supplied by the named route).",
        request_length=(10, 10), safety=_safety, side_effects=_effect,
        completion_codes=["0x00 success", "0xc7 invalid length", "0xc9 invalid token"],
        confidence="high",
    )

_update(
    (0x30, 0xE2),
    purpose="Colliding IEIT common-interface and Intel PNM reading providers.",
    request="Provider-dependent sequence of 3-byte reading descriptors.",
    response="Provider-dependent 4-byte reading records; an empty live request produced no reply.",
    request_length=(None, None), safety="disruptive",
    side_effects="Can suppress the reply and leave the emulated IPMI service unhealthy.",
    confidence="high collision; runtime winner unresolved",
)

_update(
    (0x34, 0x1A),
    purpose="Change PCIe/I2C device scanning and route the I2C mux to SmartNIC.",
    request="Exactly one selector byte: 0x09 disables scans; 0x0a enables scans.",
    response="No response data.", request_length=(1, 1), safety="disruptive",
    side_effects="Mutates live device scanning and I2C routing.", confidence="high",
)
for _selector, _operation, _effect in (
    (0x09, "Disable PCIe/I2C scans and switch to SmartNIC", "Hides scanned devices and changes the live I2C mux."),
    (0x0A, "Enable PCIe/I2C scans", "Re-enables scans but does not restore the I2C mux."),
):
    _leaf(
        (0x34, 0x1A), bytes([_selector]), name=_operation, purpose=_operation + ".",
        request=f"Fixed selector 0x{_selector:02x} (supplied by the named route).",
        request_length=(1, 1), safety="disruptive", side_effects=_effect,
        completion_codes=["0x00 success", "0xc7 invalid length", "0xcc invalid selector"],
        confidence="high",
    )

_update(
    (0x38, 0x11),
    purpose="Read current BIOS configuration states through the runtime translation map.",
    request="Exactly group and item bytes; item 0xff returns every present item in the group.",
    response="Reserved 0x00, count, then count state bytes (maximum 33).",
    request_length=(2, 2), safety="read-only", side_effects="None.", confidence="high",
)
_update(
    (0x38, 0x12),
    purpose="Write a pending BIOS state or invoke a mapped live BMC setter.",
    request="At least group, item, and state bytes; trailing bytes are ignored.",
    response="No response data.", request_length=(3, None), safety="state-changing",
    side_effects="Writes pending BIOS settings; selected records change live power, network, or SOL state.",
    confidence="high",
)

_records = _PLATFORM_CATALOG["bios_translation"]["records"]
_attributes: dict[tuple[int, int], str] = {}
for _record in _records:
    _attributes[(_record["group"], _record["item"])] = _record["attribute"]
    _leaf(
        (0x38, 0x12),
        bytes([_record["group"], _record["item"], _record["state"]]),
        name=f"Set BIOS {_record['attribute']} = {_record['meaning']}",
        purpose=(
            f"Set {_record['attribute']} to {_record['meaning']} using embedded build-default "
            "translation data; the deployed runtime JSON can replace this mapping."
        ),
        request="Fixed group, item, and state tuple supplied by the named route.",
        request_length=(3, 3), safety="state-changing",
        side_effects="Changes a pending BIOS setting or a mapped live BMC setting.",
        completion_codes=[
            "0x00 success", "0xc7 request too short", "0xc9 unknown tuple",
            "0xd3 runtime translation/settings JSON unavailable",
        ],
        confidence="high build-default mapping; runtime data-driven",
    )
for (_group, _item), _attribute in sorted(_attributes.items()):
    _leaf(
        (0x38, 0x11), bytes([_group, _item]), name=f"Read BIOS {_attribute}",
        purpose=(
            f"Read the current state for {_attribute}; the deployed runtime JSON can replace "
            "the embedded build-default mapping."
        ),
        request="Fixed group and item tuple supplied by the named route.",
        request_length=(2, 2), safety="read-only", side_effects="None.",
        completion_codes=[
            "0x00 success", "0xc7 invalid length", "0xc9 unknown tuple",
            "0xd3 runtime settings JSON unavailable",
        ],
        confidence="high build-default mapping; runtime data-driven",
    )
for _group in sorted({_record["group"] for _record in _records}):
    _leaf(
        (0x38, 0x11), bytes([_group, 0xFF]), name=f"Read all BIOS settings in group {_group}",
        purpose=f"Read every present BIOS setting state in group {_group} (maximum 33).",
        request="Fixed group and item 0xff tuple supplied by the named route.",
        request_length=(2, 2), safety="read-only", side_effects="None.", confidence="high",
    )

# Add contracts recovered from the non-AMI/non-PDK provider layers.  Preserve
# the 0x30/0xe2 collision summary and add PNM as a separately named wire route.
for _aux_source in _AUX_CATALOG["contracts"]:
    _aux_address = (int(_aux_source["netfn"], 0), int(_aux_source["command"], 0))
    _aux_route = ((*_aux_address, 0x101)
                  if _aux_source["id"] == "intel-pnm-get-reading"
                  else _aux_address)
    IEIT_COMMANDS[_aux_route] = _aux_contract(_aux_source)

# Expand every AMI NetFn 0x32 registration into its target-proven operations.
for _ami_registration in _AMI_CATALOG["registrations"]:
    for _ami_operation in _ami_registration["normalized_operations"]:
        _ami_operation_contract = _ami_contract(_ami_registration, _ami_operation)
        _ami_address = (_ami_registration["netfn"], _ami_registration["cmd"])
        _ami_prefix = _ami_operation_contract["prefix"]
        _ami_selector = _ami_operation_contract["selector"]
        if _ami_prefix:
            _ami_route = (*_ami_address, *_ami_prefix)
        elif _ami_selector:
            _ami_route = (
                *_ami_address,
                0x100 + _ami_operation_contract["selector_offset"],
                *_ami_selector,
            )
        else:
            _ami_route = _ami_address
        IEIT_COMMANDS[_ami_route] = _ami_operation_contract

# Add the semantic operations recovered from all 129 IEIT PDK registrations.
# A selector after caller-controlled bytes cannot be auto-prefixed; the key's
# >0xff sentinel only disambiguates that named route inside this dictionary.
for _pdk_registration in _PDK_CATALOG["registrations"]:
    for _operation in _pdk_registration["operations"]:
        _netfn = int(_operation["netfn"], 0)
        _cmd = int(_operation["cmd"], 0)
        _operation_contract = _pdk_contract(_pdk_registration, _operation)
        _prefix = _operation_contract["prefix"]
        _selector = _operation_contract["selector"]
        if _prefix:
            _route = (_netfn, _cmd, *_prefix)
        elif _selector:
            _route = (
                _netfn, _cmd,
                0x100 + _operation_contract["selector_offset"],
                *_selector,
            )
        else:
            _route = (_netfn, _cmd)
        IEIT_COMMANDS[_route] = _operation_contract

# A documented name must resolve to exactly one route.  Disambiguate repeated
# short operation names with real wire identity, never the >0xff dictionary
# sentinel used for selectors that occur after caller-controlled bytes.
_routes_by_name: dict[str, list[tuple[int, ...]]] = defaultdict(list)
for _route, _operation_contract in IEIT_COMMANDS.items():
    _routes_by_name[_operation_contract["name"]].append(_route)
for _routes in _routes_by_name.values():
    if len(_routes) < 2:
        continue
    for _route in _routes:
        _operation_contract = IEIT_COMMANDS[_route]
        _identity = _operation_contract.get("route_identity")
        if _identity is None:
            _identity = bytes(_route[2:])
        _suffix = f"_{_route[0]:02X}_{_route[1]:02X}"
        if _identity:
            _offset = _operation_contract.get("selector_offset")
            if _offset not in (None, 0):
                _suffix += f"_AT{_offset}"
            _suffix += "_" + "_".join(f"{byte:02X}" for byte in _identity)
        _operation_contract["name"] += _suffix

IEIT_CMD_NAMES: dict[tuple[int, ...], str] = {
    address: f"IEIT {contract['name']}"
    for address, contract in IEIT_COMMANDS.items()
    if all(byte <= 0xff for byte in address)
}

register("ieit", None, IEIT_CMD_NAMES)


__all__ = [
    "IEIT_COMMANDS",
    "IEIT_CMD_NAMES",
    "IEIT_FIRMWARE_SHA256",
    "IEIT_PDK_SHA256",
    "IEIT_REGISTRATIONS",
]
