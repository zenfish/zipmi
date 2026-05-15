"""
zipmi.consts — IPMI protocol constants (NetFn, completion codes, auth, priv).

WHAT     Authoritative enum dicts for IPMI 1.5 / 2.0 / RMCP+ field values used
         across the Scapy layers and the higher-level API.
WHY      A single source of truth for byte values keeps dissection labels and
         CLI output consistent and avoids drift between modules.
SUCCESS  `from zipmi import consts; consts.NETFN[6] == "App"`.
TARGET   IPMI 1.5 spec §5.1 (NetFn), §5.2 (Completion Codes); IPMI 2.0 §13
         (RMCP+ session, cipher suites).
RELATED  IPMI-1.5.pdf, IPMI2.0-markup.pdf in ~/phd/dox/specs/
"""

from __future__ import annotations

# RMCP class field (IPMI 1.5 §13.1.3, RFC 4413, DSP0136 §3.2.2).
# Bit 7 = ACK indicator; bits 6-5 reserved; bits 4-0 = class.
# Class values per RFC 4413: 0-5 reserved, 6 = ASF, 7 = IPMI, 8-31 reserved.
RMCP_CLASS = {
    0x06: "ASF",
    0x07: "IPMI",
}

# RMCP version (always 0x06 = ASF 2.0)
RMCP_VERSION = 0x06

# IPMI Network Function codes (IPMI 1.5 §5.1, table 5-1).
# Even = Request, Odd = Response. We label by request code; response is +1.
NETFN = {
    0x00: "Chassis",
    0x02: "Bridge",
    0x04: "SensorEvent",
    0x06: "App",
    0x08: "Firmware",
    0x0A: "Storage",
    0x0C: "Transport",
    0x2C: "Group",
    0x2E: "OEM/Group",
    0x30: "ControllerOEM",
}

# IPMI Authentication Types (1.5 §13.6 / 2.0 §13.6).
AUTH_TYPE = {
    0x00: "None",
    0x01: "MD2",
    0x02: "MD5",
    0x04: "StraightPwd",
    0x05: "OEM",
    0x06: "RMCP+",  # IPMI 2.0 lanplus; triggers RMCP+ session header.
}

# Privilege levels (IPMI 1.5 §6.7).
PRIV_LEVEL = {
    0x00: "Reserved",
    0x01: "Callback",
    0x02: "User",
    0x03: "Operator",
    0x04: "Administrator",
    0x05: "OEM",
}

# Completion codes (IPMI 1.5 §5.2, table 5-2). Subset; full table grows over
# time as commands are added.
COMP_CODE = {
    0x00: "Success",
    0xC0: "Node Busy",
    0xC1: "Invalid command",
    0xC2: "Invalid command for given LUN",
    0xC3: "Timeout while processing command",
    0xC4: "Out of storage space on BMC",
    0xC5: "Reservation canceled or invalid reservation ID",
    0xC6: "Request data truncated",
    0xC7: "Request data length invalid",
    0xC8: "Request data field length limit exceeded",
    0xC9: "Parameter out of range",
    0xCA: "Cannot return number of requested data bytes",
    0xCB: "Requested sensor, data, or record not present",
    0xCC: "Invalid data field in request",
    0xCD: "Command illegal for specified sensor or record type",
    0xCE: "Command response could not be provided",
    0xCF: "Cannot execute duplicated request",
    0xD0: "SDR repository in update mode",
    0xD1: "Device in firmware update mode",
    0xD2: "BMC initialization in progress",
    0xD3: "Internal destination unavailable",
    0xD4: "Insufficient privilege level or firmware firewall",
    0xD5: "Command not supported in present state",
    0xD6: "Cannot execute command because subfunction disabled or unavailable",
    0xFF: "Unspecified",
}

# IANA Enterprise Numbers used in this codebase.
IANA = {
    4542:  "ASF",        # ASF 2.0 / DSP0136
    674:   "Dell",
    10876: "Supermicro",
    343:   "Intel",
}

# Best-effort BMC generation guess from (manufacturer IANA, product ID).
# Sourced from prior firmware RE — Dell never published a definitive map,
# so anything not listed is best-guessed by the high byte of product_id.
# Marked "(guess)" in the CLI to make the uncertainty explicit.
BMC_GENERATION = {
    (674, 0x0100): "iDRAC6 (Monolithic)",
    (674, 0x0101): "iDRAC6 Modular",
    (674, 0x0102): "iDRAC7 (Monolithic)",
    (674, 0x0103): "iDRAC7 Modular",
    (674, 0x0200): "iDRAC8",
    (674, 0x0201): "iDRAC8 Modular",
    (674, 0x0300): "iDRAC9",
    (674, 0x0301): "iDRAC9 Modular",
    (674, 0x0400): "iDRAC10",
    # Supermicro: BMC chip family, not a single product line. Leave blank
    # so the CLI falls back to the byte-pattern heuristic.
}


def guess_bmc_generation(iana: int, product_id: int) -> str:
    """Return a human label for the BMC generation, or 'unknown'.

    Exact match wins; otherwise infer Dell generation from the high byte
    of product_id (0x01xx → iDRAC6, 0x02xx → iDRAC8, 0x03xx → iDRAC9, …)
    and tag with '(guess)' so callers know the fingerprint isn't certain.
    """
    if (iana, product_id) in BMC_GENERATION:
        return BMC_GENERATION[(iana, product_id)]
    if iana == 674:
        family = (product_id >> 8) & 0xFF
        guess = {
            0x01: "iDRAC6", 0x02: "iDRAC8", 0x03: "iDRAC9", 0x04: "iDRAC10",
        }.get(family)
        if guess:
            return f"{guess} (guess)"
    return "unknown"
