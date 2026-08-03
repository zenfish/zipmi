"""
zipmi.scapy_ipmi.groups.dcmi — DCMI (Data Center Manageability Interface).

WHAT     DCMI 1.5 group-specific cmd table. NetFn 0x2C request /
         0x2D response, group code 0xDC ("DCGRP" in the spec).

WHY      DCMI is the de-facto standard for power / thermal / asset
         monitoring across data-centre BMCs (Intel servers, Dell, HP,
         Lenovo, Supermicro all implement at least the mandatory
         subset). Knowing the cmd surface is essential for power-cap
         attack research and for fingerprinting BMC capability tiers.

SUCCESS  After loading this module, GROUP_CMD_NAMES[(0xDC, 0x01)] ==
         "Get DCMI Capabilities Info".

REFS     DCMI 1.5 specification — Table 6-1
         "Command Definition" page 24-25.
         Spec source: https://www.intel.com/content/dam/www/public/us/
         en/documents/technical-specifications/dcmi-v1-5-rev-spec.pdf

NOTES    Table 6-1 lists more rows than appear here — the rest are
         baseline IPMI cmds that DCMI requires the BMC to implement
         (Get Device ID, Get Chassis Status, Get Sensor Reading, ...).
         Those live in their own NetFns (0x06 App, 0x00 Chassis,
         0x04 S/E, etc.) and are already covered by cmd_names.
         This module only registers the DCGRP-specific cmds — the
         ones that *only* exist under the 0x2C/0xDC envelope.
"""
from __future__ import annotations

from ._registry import register


# Group code per DCMI 1.5 §6 — DCGRP = 0xDCh, used as the first data
# byte of every NetFn 0x2C/0x2D DCMI message.
DCMI_GROUP_CODE = 0xDC


# (group_code, cmd) → human-readable name.
# Source: DCMI 1.5 Table 6-1, DCGRP rows only.
DCMI_CMD_NAMES: dict[tuple[int, int], str] = {
    # Capabilities & Discovery / Configuration
    (0xDC, 0x01): "DCMI Get DCMI Capabilities Info",
    (0xDC, 0x12): "DCMI Set DCMI Configuration Parameters",
    (0xDC, 0x13): "DCMI Get DCMI Configuration Parameters",
    (0xDC, 0x09): "DCMI Get Management Controller Identifier String",
    (0xDC, 0x0A): "DCMI Set Management Controller Identifier String",
    # Platform & Asset Identification
    (0xDC, 0x06): "DCMI Get Asset Tag",
    (0xDC, 0x08): "DCMI Set Asset Tag",
    # Sensor / SDR
    (0xDC, 0x07): "DCMI Get DCMI Sensor Info",
    # Power Management
    (0xDC, 0x02): "DCMI Get Power Reading",
    (0xDC, 0x03): "DCMI Get Power Limit",
    (0xDC, 0x04): "DCMI Set Power Limit",
    (0xDC, 0x05): "DCMI Activate/Deactivate Power Limit",
    # Thermal Management
    (0xDC, 0x0B): "DCMI Set Thermal Limit",
    (0xDC, 0x0C): "DCMI Get Thermal Limit",
    (0xDC, 0x10): "DCMI Get Temperature Readings",
}


# Privilege-level + mandatory/optional metadata from Table 6-1, used by
# the catalogue printer in cli/oem_cmds.py.
DCMI_META: dict[tuple[int, int], dict[str, str]] = {
    (0xDC, 0x01): {"priv": "Session-less", "mo": "M",
                   "desc": "Capabilities, version, supported optional features"},
    (0xDC, 0x12): {"priv": "Admin",  "mo": "M",
                   "desc": "Set DCMI config (activate / deactivate limit, etc.)"},
    (0xDC, 0x13): {"priv": "User",   "mo": "M",
                   "desc": "Read DCMI config parameters"},
    (0xDC, 0x09): {"priv": "User",   "mo": "M",
                   "desc": "Get MC identifier string"},
    (0xDC, 0x0A): {"priv": "Admin",  "mo": "M", "desc": "Set MC identifier string"},
    (0xDC, 0x06): {"priv": "User",   "mo": "M", "desc": "Get asset tag (16B chunks)"},
    (0xDC, 0x08): {"priv": "Operator", "mo": "M", "desc": "Set asset tag"},
    (0xDC, 0x07): {"priv": "Operator", "mo": "M",
                   "desc": "Discover DCMI sensors per Entity ID"},
    (0xDC, 0x02): {"priv": "User",   "mo": "O",
                   "desc": "Power reading: current / min / max / avg over interval"},
    (0xDC, 0x03): {"priv": "User",   "mo": "O", "desc": "Get current power limit + action"},
    (0xDC, 0x04): {"priv": "Operator", "mo": "O",
                   "desc": "Set power-cap (watts, exception action, sample period)"},
    (0xDC, 0x05): {"priv": "Operator", "mo": "O",
                   "desc": "Toggle power-limit enforcement on/off"},
    (0xDC, 0x0B): {"priv": "Operator", "mo": "O",
                   "desc": "Set thermal limit per entity (inlet temp ceiling)"},
    (0xDC, 0x0C): {"priv": "User",   "mo": "O", "desc": "Get thermal limit"},
    (0xDC, 0x10): {"priv": "User",   "mo": "M",
                   "desc": "Per-entity inlet/CPU/baseboard temperature readings"},
}


# --------------------------------------------------------------------------
# ipmitool-style verbs.
#
# `ipmitool dcmi <verb>` is what most users actually type. Map those
# verbs to the (group, cmd) tuple plus any byte prefix the verb implies
# (power activate vs deactivate share cmd 0x05; the first data byte
# selects the action).
#
# Order matters for the listing: matches the ipmitool subcommand order
# so help output looks familiar. Multi-word verbs (e.g. "power reading")
# are matched longest-first by the CLI dispatcher, so "power activate"
# wins over plain "power".
# --------------------------------------------------------------------------
DCMI_VERBS: list[dict] = [
    {"verb": "discover",          "key": (0xDC, 0x01), "prefix": b""},
    {"verb": "power reading",     "key": (0xDC, 0x02)},
    {"verb": "power get_limit",   "key": (0xDC, 0x03)},
    {"verb": "power set_limit",   "key": (0xDC, 0x04)},
    {"verb": "power activate",    "key": (0xDC, 0x05), "prefix": b"\x01\x00\x00"},
    {"verb": "power deactivate",  "key": (0xDC, 0x05), "prefix": b"\x02\x00\x00"},
    {"verb": "sensors",           "key": (0xDC, 0x07)},
    {"verb": "asset_tag",         "key": (0xDC, 0x06)},
    {"verb": "set_asset_tag",     "key": (0xDC, 0x08)},
    {"verb": "get_mc_id_string",  "key": (0xDC, 0x09)},
    {"verb": "set_mc_id_string",  "key": (0xDC, 0x0A)},
    {"verb": "thermalpolicy get", "key": (0xDC, 0x0C)},
    {"verb": "thermalpolicy set", "key": (0xDC, 0x0B)},
    {"verb": "get_temp_reading",  "key": (0xDC, 0x10)},
    {"verb": "get_conf_param",    "key": (0xDC, 0x13)},
    {"verb": "set_conf_param",    "key": (0xDC, 0x12)},
    # oob_discover (RMCP/ASF Ping with DCMI capabilities bit) is NOT a
    # NetFn 0x2C cmd — it rides RMCP class 0x06. Use `zipmi scan asf-ping`.
]


register("dcmi", DCMI_GROUP_CODE, DCMI_CMD_NAMES)
