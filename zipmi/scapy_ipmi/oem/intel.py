"""
zipmi.scapy_ipmi.oem.intel — Intel OpenBMC OEM commands (IANA 343).

WHAT     Command-name table for the `intel-ipmi-oem` provider that ships on
         Intel server-board OpenBMC builds (the largest OEM surface in the
         OpenBMC ecosystem). Covers the pure-OEM vendor NetFns
         0x30 (General), 0x32 (Platform), 0x3E (App) and the OEM firmware-
         update state machine that overrides NetFn 0x08.

WHY      Intel boards are the most-seen identifiable OpenBMC flavor in our
         internet survey (see the OpenBMC OEM IPMI survey (upstream source review)).
         Several commands are directly attack-relevant: Set Special User
         Password (0x30/0x5F), Control BMC Services (0x30/0xB1), the
         manufacturing-mode unlocks (0x30/0xA4,0xB5), Get BIOS Password Hash
         (0x30/0xD8) and the raw firmware-write path (0x08/0x2C).

WIRE     Most intel-ipmi-oem commands use RAW vendor NetFns and do not put
         IANA 343 on the wire. Intel Node Manager is the exception: the X14-
         shipped provider uses NetFn 0x2E plus the little-endian IANA prefix
         57 01 00. Those named routes bake in that prefix.

LOAD     `zipmi.load_vendor("intel")`

SOURCE   github.com/openbmc/intel-ipmi-oem (catalogued from source in
         the OpenBMC OEM IPMI survey (upstream source review) §2.1).
         netFnGeneral=0x30, netFnPlatform=0x32, netFnApp=0x3E
         (include/oemcommands.hpp).
"""

from __future__ import annotations

from scapy.fields import ByteEnumField, LEX3BytesField, XByteField
from scapy.packet import Packet

from ..commands import COMP_CODE
from ._registry import build_fixed_packet_class, register


INTEL_IANA = 343


# --- pure-OEM vendor-NetFn commands --------------------------------------

INTEL_GENERAL = 0x30   # netFnGeneral
INTEL_PLATFORM = 0x32  # netFnPlatform
INTEL_APP = 0x3E       # netFnApp
INTEL_FIRMWARE = 0x08  # standard Firmware NetFn, overridden by Intel OEM block
INTEL_NM = 0x2E
INTEL_NM_IANA_PREFIX = (0x57, 0x01, 0x00)
INTEL_NM_PROVIDER_SHA256 = "aeb0d02d844e5add09b70bdb44b55ecd95362b880b478074a2a08acdcb13e03c"
INTEL_NM_PROVIDER_BUILD_ID = "9093c1f651cbea59044b7a06d0e3a22df018fe66"

INTEL_CMD_NAMES: dict[tuple[int, ...], str] = {
    (0x30, 0x01): "Intel Get BMC Version String",
    (0x30, 0x02): "Intel Restore Configuration",
    (0x30, 0x14): "Intel MTM Get Signal",
    (0x30, 0x15): "Intel MTM Set Signal",
    (0x30, 0x27): "Intel Get OEM Device Info",
    (0x30, 0x2D): "Intel Set Cold Redundancy Config",
    (0x30, 0x2E): "Intel Get Cold Redundancy Config",
    (0x30, 0x33): "Intel Get Multi-Node Role",
    (0x30, 0x36): "Intel Get Multi-Node ID",
    (0x30, 0x42): "Intel Disable BMC System Reset",
    (0x30, 0x43): "Intel Get BMC Reset Disables",
    (0x30, 0x44): "Intel Send Embedded FW Update Status",
    (0x30, 0x57): "Intel Set Fault Indication",
    (0x30, 0x5A): "Intel Set OEM User2 Activation",
    (0x30, 0x5F): "Intel Set Special User Password",
    (0x30, 0x63): "Intel Get Multi-Node Presence",
    (0x30, 0x66): "Intel Get Buffer Size",
    (0x30, 0x89): "Intel Set Fan Config",
    (0x30, 0x8A): "Intel Get Fan Config",
    (0x30, 0x8C): "Intel Set Fan Speed Offset",
    (0x30, 0x8D): "Intel Get Fan Speed Offset",
    (0x30, 0x8E): "Intel Set DIMM Offset",
    (0x30, 0x8F): "Intel Get DIMM Offset",
    (0x30, 0x90): "Intel Set FSC Parameter",
    (0x30, 0x91): "Intel Get FSC Parameter",
    (0x30, 0x93): "Intel Read Base Board Product ID",
    (0x30, 0x9A): "Intel Get Processor Err Config",
    (0x30, 0x9B): "Intel Set Processor Err Config",
    (0x30, 0xA1): "Intel Set Manufacturing Data",
    (0x30, 0xA2): "Intel Get Manufacturing Data",
    (0x30, 0xA3): "Intel Set FITc Layout",
    (0x30, 0xA4): "Intel MTM BMC Feature Control",
    (0x30, 0xB0): "Intel Get LED Status",
    (0x30, 0xB1): "Intel Control BMC Services",
    (0x30, 0xB2): "Intel Get BMC Service Status",
    (0x30, 0xB3): "Intel Get Security Mode",
    (0x30, 0xB4): "Intel Set Security Mode",
    (0x30, 0xB5, 0x00, 0x49, 0x4E, 0x54, 0x45, 0x4C): "Intel MTM Keep Alive",  # guard: reserved 0x00 + "INTEL" (manufacturingcommands.cpp:826)
    (0x30, 0xD3): "Intel Set BIOS Capability",
    (0x30, 0xD4): "Intel Get BIOS Capability",
    (0x30, 0xD5): "Intel Set Payload",
    (0x30, 0xD6): "Intel Get Payload",
    (0x30, 0xD7): "Intel Set BIOS Pwd Hash Info",
    (0x30, 0xD8): "Intel Get BIOS Pwd Hash",
    (0x30, 0xE2): "Intel OEM Get Reading",
    (0x30, 0xE5): "Intel Get NMI Source/Status",
    (0x30, 0xEA): "Intel Set EFI Boot Options",
    (0x30, 0xEB): "Intel Get EFI Boot Options",
    (0x30, 0xED): "Intel Set NMI Source/Status",
    (0x30, 0xEF): "Intel Get PSU Version",
    (0x32, 0x91): "Intel Clear CMOS",
    (0x3E, 0x30): "Intel MDR-II Agent Status",
    (0x3E, 0x31): "Intel MDR-II Get Dir",
    (0x3E, 0x32): "Intel MDR-II Get Data Info",
    (0x3E, 0x33): "Intel MDR-II Lock Data",
    (0x3E, 0x34): "Intel MDR-II Unlock Data",
    (0x3E, 0x35): "Intel MDR-II Get Data Block",
    (0x3E, 0x36): "Intel MDR-II Send Data Info Offer",
    (0x3E, 0x37): "Intel MDR-II Send Data Info",
    (0x3E, 0x38): "Intel MDR-II Data Start",
    (0x3E, 0x39): "Intel MDR-II Data Done",
    (0x3E, 0x3A): "Intel MDR-II Send Data Block",
    (0x3E, 0x51): "Intel Slot IPMB",
    (0x3E, 0x84): "Intel PFR Mailbox Read",
    # OEM firmware-update state machine (overrides NetFn 0x08).
    (0x08, 0x20): "Intel Get FW Version Info",
    (0x08, 0x21): "Intel Get FW Security Version",
    (0x08, 0x22): "Intel Get FW Update Channel Info",
    (0x08, 0x23): "Intel Get BMC Execution Context",
    (0x08, 0x25): "Intel Get FW Root Cert Data",
    (0x08, 0x26): "Intel Get FW Update Random Number",
    (0x08, 0x27): "Intel Set Firmware Update Mode",
    (0x08, 0x28): "Intel Exit FW Update Mode",
    (0x08, 0x29): "Intel Get/Set FW Update Control",
    (0x08, 0x2A): "Intel Get FW Update Status",
    (0x08, 0x2B): "Intel Set FW Update Options",
    (0x08, 0x2C): "Intel FW Image Write Data",
    # App (0x06) override: raw I2C master passthrough.
    (0x06, 0x52): "Intel Controller (Master) Write-Read",
    # Intel Node Manager provider shipped in the Supermicro X14 image.
    (0x2E, 0xC0, *INTEL_NM_IANA_PREFIX): "Intel NM Enable/Disable Policy Control",
    (0x2E, 0xC1, *INTEL_NM_IANA_PREFIX): "Intel NM Set Policy",
    (0x2E, 0xC2, *INTEL_NM_IANA_PREFIX): "Intel NM Get Policy",
    (0x2E, 0xC7, *INTEL_NM_IANA_PREFIX): "Intel NM Reset Statistics",
    (0x2E, 0xC8, *INTEL_NM_IANA_PREFIX): "Intel NM Get Statistics",
    (0x2E, 0xC9, *INTEL_NM_IANA_PREFIX): "Intel NM Get Capabilities",
    (0x2E, 0xCA, *INTEL_NM_IANA_PREFIX): "Intel NM Get Version",
    (0x2E, 0xCB, *INTEL_NM_IANA_PREFIX): "Intel NM Set Power Draw Range",
    (0x2E, 0xD0, *INTEL_NM_IANA_PREFIX): "Intel NM Set Total Power Budget",
    (0x2E, 0xD1, *INTEL_NM_IANA_PREFIX): "Intel NM Get Total Power Budget",
    (0x2E, 0xF2, *INTEL_NM_IANA_PREFIX): "Intel NM Get Limiting Policy ID",
}


def _field(offset: str, name: str, kind: str, meaning: str) -> dict[str, str]:
    return {"offset": offset, "name": name, "type": kind, "meaning": meaning}


_IANA_FIELDS = [
    {"name": "iana0", "kind": "u8", "constant": 0x57},
    {"name": "iana1", "kind": "u8", "constant": 0x01},
    {"name": "iana2", "kind": "u8", "constant": 0x00},
]


# Layouts include the mandatory three-byte IANA prefix. Response layouts also
# include the completion-code byte because decode_payload_response prepends it.
_INTEL_NM_LAYOUTS = {
    0xC0: (
        [{"name": "action", "kind": "u8"}, {"name": "domain", "kind": "u8"},
         {"name": "policy_id", "kind": "u8"}], []),
    0xC1: (
        [{"name": "domain_enabled", "kind": "u8"}, {"name": "policy_id", "kind": "u8"},
         {"name": "trigger_config", "kind": "u8"}, {"name": "alert_shutdown", "kind": "u8"},
         {"name": "limit", "kind": "u16le"}, {"name": "correction_time", "kind": "u32le"},
         {"name": "trigger_limit", "kind": "u16le"},
         {"name": "statistics_period", "kind": "u16le"}], []),
    0xC2: (
        [{"name": "domain", "kind": "u8"}, {"name": "policy_id", "kind": "u8"}],
        [{"name": "domain_state", "kind": "u8"}, {"name": "trigger_type", "kind": "u8"},
         {"name": "alert_shutdown", "kind": "u8"}, {"name": "limit", "kind": "u16le"},
         {"name": "correction_time", "kind": "u32le"},
         {"name": "trigger_limit", "kind": "u16le"},
         {"name": "statistics_period", "kind": "u16le"}]),
    0xC7: (
        [{"name": "mode", "kind": "u8"}, {"name": "domain", "kind": "u8"},
         {"name": "policy_component_id", "kind": "u8"}], []),
    0xC8: (
        [{"name": "mode", "kind": "u8"}, {"name": "domain_flags", "kind": "u8"},
         {"name": "policy_component_id", "kind": "u8"}],
        [{"name": "current", "kind": "u16le"}, {"name": "minimum", "kind": "u16le"},
         {"name": "maximum", "kind": "u16le"}, {"name": "average", "kind": "u16le"},
         {"name": "timestamp", "kind": "u32le"},
         {"name": "reporting_period", "kind": "u32le"},
         {"name": "domain_state", "kind": "u8"}]),
    0xC9: (
        [{"name": "domain", "kind": "u8"}, {"name": "trigger_policy_type", "kind": "u8"}],
        [{"name": "max_concurrent_settings", "kind": "u8"},
         {"name": "max_limit", "kind": "u16le"}, {"name": "min_limit", "kind": "u16le"},
         {"name": "min_correction_time", "kind": "u32le"},
         {"name": "max_correction_time", "kind": "u32le"},
         {"name": "min_statistics_period", "kind": "u16le"},
         {"name": "max_statistics_period", "kind": "u16le"},
         {"name": "domain", "kind": "u8"}]),
    0xCA: ([], [
        {"name": "nm_version", "kind": "u8"}, {"name": "ipmi_version", "kind": "u8"},
        {"name": "firmware_patch", "kind": "u8"}, {"name": "firmware_major", "kind": "u8"},
        {"name": "firmware_minor", "kind": "u8"},
    ]),
    0xCB: (
        [{"name": "domain", "kind": "u8"}, {"name": "minimum_power", "kind": "u16le"},
         {"name": "maximum_power", "kind": "u16le"}], []),
    0xD0: (
        [{"name": "domain_component", "kind": "u8"}, {"name": "budget", "kind": "u16le"},
         {"name": "component_id", "kind": "u8"}], []),
    0xD1: (
        [{"name": "domain_component", "kind": "u8"}, {"name": "component_id", "kind": "u8"}],
        [{"name": "budget", "kind": "u16le"}]),
    0xF2: (
        [{"name": "domain", "kind": "u8"}],
        [{"name": "limiting_policy_id", "kind": "u8"}]),
}


_INTEL_NM_META = {
    0xC0: ("Enable/Disable Policy Control", "Administrator", "state-changing", "Enables or disables global, domain, or per-policy control through D-Bus policy state.", "0x00 success; 0x80 invalid policy; 0x81 invalid domain; 0xcc invalid field; 0xc7 wrong length; 0xd4 insufficient privilege; 0xff backend failure"),
    0xC1: ("Set Policy", "Administrator", "state-changing", "Creates, updates, deletes, or enables a Node Manager policy through PolicyManager D-Bus.", "0x00 success; 0x80 invalid policy; 0x81 invalid domain; mapped policy/range errors; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xC2: ("Get Policy", "User", "read-only", "Reads one Node Manager policy.", "0x00 success; 0x80 invalid policy; 0x81 invalid domain; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xC7: ("Reset Statistics", "Administrator", "state-changing", "Resets statistics for the selected mode and scope.", "0x00 success; 0x81 invalid domain; 0x88 invalid mode; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xC8: ("Get Statistics", "User", "read-only", "Reads statistics or the energy accumulator for the selected scope.", "0x00 success; 0x80 invalid policy/component; 0x81 invalid domain; 0x88 invalid mode; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xC9: ("Get Capabilities", "User", "read-only", "Reads Node Manager limits for a domain, trigger, and policy type.", "0x00 success; 0x81 invalid domain; 0x82 invalid policy type; 0x83 invalid trigger type; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xCA: ("Get Version", "User", "read-only", "Reads the active Node Manager and firmware versions.", "0x00 success; 0xc7 wrong length; 0xff active-version lookup or parse failure"),
    0xCB: ("Set Power Draw Range", "Administrator", "state-changing", "Persistently updates domain minimum and maximum power; out-of-range policies may be disabled.", "0x00 success; 0x81 invalid domain; 0xc9 invalid range; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xD0: ("Set Total Power Budget", "Administrator", "state-changing", "Sets the selected domain or component Budget property using the X14 per-component extension.", "0x00 success; 0x81 invalid domain; 0x84 budget out of range; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xD1: ("Get Total Power Budget", "User", "read-only", "Reads the selected domain or component Budget property using the X14 per-component extension.", "0x00 success; 0x80 invalid component; 0x81 invalid domain; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
    0xF2: ("Get Limiting Policy ID", "User", "read-only", "Reads the selected limiting policy ID.", "0x00 success; 0x81 invalid domain; 0xa1 no limiting policy; 0xcc invalid field; 0xc7 wrong length; 0xff backend failure"),
}


_INTEL_NM_HANDLERS = {
    0xC0: "enableNmPolicyControl", 0xC1: "setNmPolicy",
    0xC2: "getNodeManagerPolicy", 0xC7: "resetNmStatistics",
    0xC8: "getNmStatistics", 0xC9: "getNmCapabilities",
    0xCA: "getNmVersion", 0xCB: "setNmPowerDrawRange",
    0xD0: "setTotalPowerBudget", 0xD1: "getTotalPowerBudget",
    0xF2: "getLimitingPolicyId",
}


_INTEL_NM_REQUEST_FIELDS = {
    0xC0: [_field("3", "action", "u8 bitfield", "bits0:2 action 0..5; bits3:7 reserved"), _field("4", "domain", "u8 bitfield", "bits0:3 domain"), _field("5", "policy_id", "u8", "Policy ID")],
    0xC1: [_field("3", "domain_enabled", "u8 bitfield", "domain bits0:3; enabled bit4"), _field("4", "policy_id", "u8", "Policy ID"), _field("5", "trigger_config", "u8 bitfield", "trigger/config/correction/storage"), _field("6", "alert_shutdown", "u8 bitfield", "alert and shutdown flags"), _field("7–8", "limit", "i16le", "Policy limit"), _field("9–12", "correction_time", "u32le", "Correction time"), _field("13–14", "trigger_limit", "u16le", "Trigger limit"), _field("15–16", "statistics_period", "u16le", "Statistics period")],
    0xC2: [_field("3", "domain", "u8 bitfield", "bits0:3 domain"), _field("4", "policy_id", "u8", "Policy ID")],
    0xC7: [_field("3", "mode", "u8 bitfield", "bits0:4 mode"), _field("4", "domain", "u8 bitfield", "bits0:3 domain"), _field("5", "policy_component_id", "u8", "Policy or component ID")],
    0xC8: [_field("3", "mode", "u8 bitfield", "bits0:4 mode"), _field("4", "domain_flags", "u8 bitfield", "domain, statistics side, and per-component flag"), _field("5", "policy_component_id", "u8", "Policy or component ID")],
    0xC9: [_field("3", "domain", "u8 bitfield", "bits0:3 domain"), _field("4", "trigger_policy_type", "u8 bitfield", "trigger bits0:3; policy type bits4:6")],
    0xCA: [],
    0xCB: [_field("3", "domain", "u8 bitfield", "bits0:3 domain"), _field("4–5", "minimum_power", "u16le", "Minimum power"), _field("6–7", "maximum_power", "u16le", "Maximum power")],
    0xD0: [_field("3", "domain_component", "u8 bitfield", "domain bits0:3; per-component bit7"), _field("4–5", "budget", "u16le", "Power budget"), _field("6", "component_id", "u8", "Component ID")],
    0xD1: [_field("3", "domain_component", "u8 bitfield", "domain bits0:3; per-component bit7"), _field("4", "component_id", "u8", "Component ID")],
    0xF2: [_field("3", "domain", "u8 bitfield", "bits0:3 domain")],
}


_INTEL_NM_RESPONSE_FIELDS = {
    0xC0: [], 0xC1: [], 0xC7: [], 0xCB: [], 0xD0: [],
    0xC2: [_field("3", "policy", "13 bytes", "Policy state, trigger, limit, timing, and period")],
    0xC8: [_field("3–10", "statistics", "4×u16le or u64le", "Current/min/max/average, or energy accumulator"), _field("11–14", "timestamp", "u32le", "Timestamp"), _field("15–18", "reporting_period", "u32le", "Reporting period"), _field("19", "domain_state", "u8 bitfield", "Domain and state flags")],
    0xC9: [_field("3–20", "capabilities", "18 bytes", "Concurrent-setting, limit, timing, period, and domain bounds")],
    0xCA: [_field("3", "nm_version", "u8", "Node Manager version"), _field("4", "ipmi_version", "u8", "IPMI interface version"), _field("5–7", "firmware_version", "3 bytes", "Patch, major, minor")],
    0xD1: [_field("3–4", "budget", "u16le", "Power budget")],
    0xF2: [_field("3", "limiting_policy_id", "u8", "Limiting policy ID")],
}


INTEL_COMMANDS: dict[tuple[int, ...], dict] = {}
INTEL_NM_PAYLOADS = {}


def _layout_width(fields: list[dict]) -> int:
    return sum({"u8": 1, "u16le": 2, "u32le": 4}[field["kind"]] for field in fields)


for _cmd, (_request_body, _response_body) in _INTEL_NM_LAYOUTS.items():
    _name, _privilege, _safety, _purpose, _completion_codes = _INTEL_NM_META[_cmd]
    _key = (INTEL_NM, _cmd, *INTEL_NM_IANA_PREFIX)
    INTEL_COMMANDS[_key] = {
        "name": f"Intel NM {_name}",
        "handler": _INTEL_NM_HANDLERS[_cmd],
        "purpose": _purpose,
        "privilege": _privilege,
        "request_length": (3 + _layout_width(_request_body),) * 2,
        "response_length": (3 + _layout_width(_response_body),) * 2,
        "request_fields": [_field("0–2", "iana", "3 bytes", "Intel IANA 57 01 00")]
                          + _INTEL_NM_REQUEST_FIELDS[_cmd],
        "response_fields": [_field("0–2", "iana", "3 bytes", "Intel IANA 57 01 00")]
                           + _INTEL_NM_RESPONSE_FIELDS[_cmd],
        "safety": _safety,
        "side_effects": _purpose,
        "completion_codes": _completion_codes,
        "activation": "Unconditional priority-20 registration in the X14 libzintelnmipmicmds provider.",
        "evidence": f"{_INTEL_NM_HANDLERS[_cmd]} in provider SHA-256 {INTEL_NM_PROVIDER_SHA256}.",
        "confidence": "Exact target handler contract; correct-IANA live probe reached this handler.",
    }
    INTEL_NM_PAYLOADS[_key] = (
        build_fixed_packet_class(
            f"Intel NM {_name} Request", _IANA_FIELDS + _request_body,
            require_fields=True,
        ),
        build_fixed_packet_class(
            f"Intel NM {_name} Response",
            [{"name": "completion_code", "kind": "u8"}] + _IANA_FIELDS + _response_body,
        ),
    )


# --- decoded payloads ----------------------------------------------------

class IntelGetBmcVersionStringReq(Packet):
    """Intel Get BMC Version String (NetFn 0x30, Cmd 0x01). No request data."""

    name = "Intel Get BMC Version String Request"
    fields_desc = []

    def extract_padding(self, s):
        return b"", s


class IntelControlBmcServicesReq(Packet):
    """Intel Control BMC Services (NetFn 0x30, Cmd 0xB1).

    Enables/disables BMC network services (web, KVM, cd-media, solssh, ...).
    state 0x00 = disable, 0x01 = enable; services is a bitmask.
    """

    name = "Intel Control BMC Services Request"
    fields_desc = [
        XByteField("state", 0x00),
        LEX3BytesField("services", 0x000000),
    ]

    def extract_padding(self, s):
        return b"", s


class IntelControlBmcServicesResp(Packet):
    name = "Intel Control BMC Services Response"
    fields_desc = [ByteEnumField("comp_code", 0x00, COMP_CODE)]

    def extract_padding(self, s):
        return b"", s


class IntelGetSecurityModeResp(Packet):
    """Intel Get Security Mode (NetFn 0x30, Cmd 0xB3) response."""

    name = "Intel Get Security Mode Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("restriction_mode", 0x00),
        XByteField("special_mode", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


INTEL_PAYLOADS = {
    (0x30, 0x01): (IntelGetBmcVersionStringReq, None),
    (0x30, 0xB1): (IntelControlBmcServicesReq, IntelControlBmcServicesResp),
    (0x30, 0xB3): (None, IntelGetSecurityModeResp),
    **INTEL_NM_PAYLOADS,
}


# Probe used by vendor detection: harmless User-priv read that only Intel
# answers (returns the BMC version string). A non-0xC1 completion code means
# the intel-ipmi-oem provider is present.
INTEL_DETECT_PROBE = (0x30, 0x01)


register("intel", INTEL_IANA, INTEL_CMD_NAMES, INTEL_PAYLOADS)


__all__ = [
    "INTEL_IANA",
    "INTEL_NM",
    "INTEL_NM_IANA_PREFIX",
    "INTEL_NM_PROVIDER_SHA256",
    "INTEL_NM_PROVIDER_BUILD_ID",
    "INTEL_CMD_NAMES",
    "INTEL_COMMANDS",
    "INTEL_NM_PAYLOADS",
    "INTEL_PAYLOADS",
    "INTEL_DETECT_PROBE",
]
