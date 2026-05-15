"""
zipmi.scapy_ipmi.cmd_names — IPMI command-name lookup (Table G-1).

WHAT     Maps (netfn_request, cmd) → human-readable command name from
         IPMI 2.0 spec Appendix G, Table G-1 ("Command Number Assignments
         and Privilege Levels"). Plus session/RAKP payload-type names and
         ASF message-type names so wire-trace output can label every
         datagram class zipmi might send or receive.

WHY      The wire-trace dump in Transport.send_recv used to show byte
         counts; humans read names faster than counts. NetFn+cmd pairs
         alone are also unintuitive (0x06/0x38 vs "Get Channel Auth
         Capabilities").

SUCCESS  `zipmi -v sensor list -h <bmc>` shows command names instead of
         a byte-count column on every SEND.

RELATED  core.py:Transport._dump (consumer), oem/_registry.py
         (OEM_CMD_NAMES checked first so vendor names beat generic ones).
"""

from __future__ import annotations


# --------------------------------------------------------------------------
# IPMI 2.0 Spec Table G-1 — request NetFn (even) is the lookup key.
# Entries follow the spec's ordering by section.
# --------------------------------------------------------------------------
IPMI_CMD_NAMES: dict[tuple[int, int], str] = {
    # ---- Chassis (NetFn 0x00) ---------------------------------------------
    (0x00, 0x00): "Get Chassis Capabilities",
    (0x00, 0x01): "Get Chassis Status",
    (0x00, 0x02): "Chassis Control",
    (0x00, 0x03): "Chassis Reset",
    (0x00, 0x04): "Chassis Identify",
    (0x00, 0x05): "Set Chassis Capabilities",
    (0x00, 0x06): "Set Power Restore Policy",
    (0x00, 0x07): "Get System Restart Cause",
    (0x00, 0x08): "Set System Boot Options",
    (0x00, 0x09): "Get System Boot Options",
    (0x00, 0x0A): "Set Front Panel Button Enables",
    (0x00, 0x0B): "Set Power Cycle Interval",
    (0x00, 0x0F): "Get POH Counter",

    # ---- Bridge (NetFn 0x02) ----------------------------------------------
    (0x02, 0x00): "Get Bridge State",
    (0x02, 0x01): "Set Bridge State",
    (0x02, 0x02): "Get ICMB Address",
    (0x02, 0x03): "Set ICMB Address",
    (0x02, 0x04): "Set Bridge ProxyAddress",
    (0x02, 0x05): "Get Bridge Statistics",
    (0x02, 0x06): "Get ICMB Capabilities",
    (0x02, 0x08): "Clear Bridge Statistics",
    (0x02, 0x09): "Get Bridge Proxy Address",
    (0x02, 0x0A): "Get ICMB Connector Info",
    (0x02, 0x0B): "Get ICMB Connection ID",
    (0x02, 0x0C): "Send ICMB Connection ID",
    (0x02, 0x10): "Prepare For Discovery",
    (0x02, 0x11): "Get Addresses",
    (0x02, 0x12): "Set Discovered",
    (0x02, 0x13): "Get Chassis Device ID",
    (0x02, 0x14): "Set Chassis Device ID",
    (0x02, 0x20): "Bridge Request",
    (0x02, 0x21): "Bridge Message",
    (0x02, 0x30): "Get Event Count",
    (0x02, 0x31): "Set Event Destination",
    (0x02, 0x32): "Set Event Reception State",
    (0x02, 0x33): "Send ICMB Event Message",
    (0x02, 0x34): "Get Event Destination",
    (0x02, 0x35): "Get Event Reception State",
    (0x02, 0xC0): "Error Report",

    # ---- Sensor / Event (NetFn 0x04) --------------------------------------
    (0x04, 0x00): "Set Event Receiver",
    (0x04, 0x01): "Get Event Receiver",
    (0x04, 0x02): "Platform Event",
    (0x04, 0x10): "Get PEF Capabilities",
    (0x04, 0x11): "Arm PEF Postpone Timer",
    (0x04, 0x12): "Set PEF Configuration Parameters",
    (0x04, 0x13): "Get PEF Configuration Parameters",
    (0x04, 0x14): "Set Last Processed Event ID",
    (0x04, 0x15): "Get Last Processed Event ID",
    (0x04, 0x16): "Alert Immediate",
    (0x04, 0x17): "PET Acknowledge",
    (0x04, 0x20): "Get Device SDR Info",
    (0x04, 0x21): "Get Device SDR",
    (0x04, 0x22): "Reserve Device SDR Repository",
    (0x04, 0x23): "Get Sensor Reading Factors",
    (0x04, 0x24): "Set Sensor Hysteresis",
    (0x04, 0x25): "Get Sensor Hysteresis",
    (0x04, 0x26): "Set Sensor Threshold",
    (0x04, 0x27): "Get Sensor Threshold",
    (0x04, 0x28): "Set Sensor Event Enable",
    (0x04, 0x29): "Get Sensor Event Enable",
    (0x04, 0x2A): "Re-arm Sensor Events",
    (0x04, 0x2B): "Get Sensor Event Status",
    (0x04, 0x2D): "Get Sensor Reading",
    (0x04, 0x2E): "Set Sensor Type",
    (0x04, 0x2F): "Get Sensor Type",
    (0x04, 0x30): "Set Sensor Reading and Event Status",

    # ---- Application (NetFn 0x06) -----------------------------------------
    # IPM Device Global
    (0x06, 0x00): "(reserved)",
    (0x06, 0x01): "Get Device ID",
    (0x06, 0x02): "Cold Reset",
    (0x06, 0x03): "Warm Reset",
    (0x06, 0x04): "Get Self Test Results",
    (0x06, 0x05): "Manufacturing Test On",
    (0x06, 0x06): "Set ACPI Power State",
    (0x06, 0x07): "Get ACPI Power State",
    (0x06, 0x08): "Get Device GUID",
    (0x06, 0x09): "Get NetFn Support",
    (0x06, 0x0A): "Get Command Support",
    (0x06, 0x0B): "Get Command Sub-function Support",
    (0x06, 0x0C): "Get Configurable Commands",
    (0x06, 0x0D): "Get Configurable Command Sub-functions",
    (0x06, 0x60): "Set Command Enables",
    (0x06, 0x61): "Get Command Enables",
    (0x06, 0x62): "Set Command Sub-function Enables",
    (0x06, 0x63): "Get Command Sub-function Enables",
    (0x06, 0x64): "Get OEM NetFn IANA Support",
    # BMC Watchdog Timer
    (0x06, 0x22): "Reset Watchdog Timer",
    (0x06, 0x24): "Set Watchdog Timer",
    (0x06, 0x25): "Get Watchdog Timer",
    # BMC Device + Messaging
    (0x06, 0x2E): "Set BMC Global Enables",
    (0x06, 0x2F): "Get BMC Global Enables",
    (0x06, 0x30): "Clear Message Flags",
    (0x06, 0x31): "Get Message Flags",
    (0x06, 0x32): "Enable Message Channel Receive",
    (0x06, 0x33): "Get Message",
    (0x06, 0x34): "Send Message",
    (0x06, 0x35): "Read Event Message Buffer",
    (0x06, 0x36): "Get BT Interface Capabilities",
    (0x06, 0x37): "Get System GUID",
    (0x06, 0x58): "Set System Info Parameters",
    (0x06, 0x59): "Get System Info Parameters",
    (0x06, 0x38): "Get Channel Authentication Capabilities",
    (0x06, 0x39): "Get Session Challenge",
    (0x06, 0x3A): "Activate Session",
    (0x06, 0x3B): "Set Session Privilege Level",
    (0x06, 0x3C): "Close Session",
    (0x06, 0x3D): "Get Session Info",
    (0x06, 0x3F): "Get AuthCode",
    (0x06, 0x40): "Set Channel Access",
    (0x06, 0x41): "Get Channel Access",
    (0x06, 0x42): "Get Channel Info",
    (0x06, 0x43): "Set User Access",
    (0x06, 0x44): "Get User Access",
    (0x06, 0x45): "Set User Name",
    (0x06, 0x46): "Get User Name",
    (0x06, 0x47): "Set User Password",
    (0x06, 0x48): "Activate Payload",
    (0x06, 0x49): "Deactivate Payload",
    (0x06, 0x4A): "Get Payload Activation Status",
    (0x06, 0x4B): "Get Payload Instance Info",
    (0x06, 0x4C): "Set User Payload Access",
    (0x06, 0x4D): "Get User Payload Access",
    (0x06, 0x4E): "Get Channel Payload Support",
    (0x06, 0x4F): "Get Channel Payload Version",
    (0x06, 0x50): "Get Channel OEM Payload Info",
    (0x06, 0x52): "Master Write-Read",
    (0x06, 0x54): "Get Channel Cipher Suites",
    (0x06, 0x55): "Suspend/Resume Payload Encryption",
    (0x06, 0x56): "Set Channel Security Keys",
    (0x06, 0x57): "Get System Interface Capabilities",
    (0x06, 0x5A): "Get Authorization Privilege Level",
    (0x06, 0x5B): "Get Authentication Capabilities (v2)",
    (0x06, 0x5C): "Get Session-Less Channel Privilege Level",
    (0x06, 0x5D): "Set Session-Less Channel Privilege Level",
    (0x06, 0x5E): "Get Session-Less Channel Auth Caps",

    # ---- Firmware (NetFn 0x08) — vendor-defined; left to OEM_CMD_NAMES.

    # ---- Storage (NetFn 0x0A) ---------------------------------------------
    # FRU
    (0x0A, 0x10): "Get FRU Inventory Area Info",
    (0x0A, 0x11): "Read FRU Data",
    (0x0A, 0x12): "Write FRU Data",
    # SDR
    (0x0A, 0x20): "Get SDR Repository Info",
    (0x0A, 0x21): "Get SDR Repository Allocation Info",
    (0x0A, 0x22): "Reserve SDR Repository",
    (0x0A, 0x23): "Get SDR",
    (0x0A, 0x24): "Add SDR",
    (0x0A, 0x25): "Partial Add SDR",
    (0x0A, 0x26): "Delete SDR",
    (0x0A, 0x27): "Clear SDR Repository",
    (0x0A, 0x28): "Get SDR Repository Time",
    (0x0A, 0x29): "Set SDR Repository Time",
    (0x0A, 0x2A): "Enter SDR Repository Update Mode",
    (0x0A, 0x2B): "Exit SDR Repository Update Mode",
    (0x0A, 0x2C): "Run Initialization Agent",
    # SEL
    (0x0A, 0x40): "Get SEL Info",
    (0x0A, 0x41): "Get SEL Allocation Info",
    (0x0A, 0x42): "Reserve SEL",
    (0x0A, 0x43): "Get SEL Entry",
    (0x0A, 0x44): "Add SEL Entry",
    (0x0A, 0x45): "Partial Add SEL Entry",
    (0x0A, 0x46): "Delete SEL Entry",
    (0x0A, 0x47): "Clear SEL",
    (0x0A, 0x48): "Get SEL Time",
    (0x0A, 0x49): "Set SEL Time",
    (0x0A, 0x5A): "Get Auxiliary Log Status",
    (0x0A, 0x5B): "Set Auxiliary Log Status",
    (0x0A, 0x5C): "Get SEL Time UTC Offset",
    (0x0A, 0x5D): "Set SEL Time UTC Offset",

    # ---- Transport (NetFn 0x0C) -------------------------------------------
    # LAN
    (0x0C, 0x01): "Set LAN Configuration Parameters",
    (0x0C, 0x02): "Get LAN Configuration Parameters",
    (0x0C, 0x03): "Suspend BMC ARPs",
    (0x0C, 0x04): "Get IP/UDP/RMCP Statistics",
    # Serial / Modem
    (0x0C, 0x10): "Set Serial/Modem Configuration",
    (0x0C, 0x11): "Get Serial/Modem Configuration",
    (0x0C, 0x12): "Set Serial/Modem Mux",
    (0x0C, 0x13): "Get TAP Response Codes",
    (0x0C, 0x14): "Set PPP UDP Proxy Transmit Data",
    (0x0C, 0x15): "Get PPP UDP Proxy Transmit Data",
    (0x0C, 0x16): "Send PPP UDP Proxy Packet",
    (0x0C, 0x17): "Get PPP UDP Proxy Receive Data",
    (0x0C, 0x18): "Serial/Modem Connection Active",
    (0x0C, 0x19): "Callback",
    (0x0C, 0x1A): "Set User Callback Options",
    (0x0C, 0x1B): "Get User Callback Options",
    (0x0C, 0x1C): "Set Serial Routing Mux",
    # SOL
    (0x0C, 0x20): "SOL Activating",
    (0x0C, 0x21): "Set SOL Configuration Parameters",
    (0x0C, 0x22): "Get SOL Configuration Parameters",
    # IPMI 2.0 Transport
    (0x0C, 0x40): "Forwarded Command",
    (0x0C, 0x41): "Set Forwarded Commands",
    (0x0C, 0x42): "Get Forwarded Commands",
    (0x0C, 0x43): "Enable Forwarded Commands",
}


# OEM netfns (request side) — even values from 0x2E and 0x30..0x3E.
OEM_NETFNS: frozenset[int] = frozenset({
    0x2E,  # OEM/Group
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,  # OEM
})


# RMCP+ payload-type identifiers (IPMI 2.0 §13.27.3, Table 13-16).
RMCP_PAYLOAD_TYPES: dict[int, str] = {
    0x00: "IPMI Message",
    0x01: "SOL (serial over LAN)",
    0x02: "OEM Explicit",
    0x10: "RMCP+ Open Session Request",
    0x11: "RMCP+ Open Session Response",
    0x12: "RAKP Message 1",
    0x13: "RAKP Message 2",
    0x14: "RAKP Message 3",
    0x15: "RAKP Message 4",
}


# ASF v2.0 message types (DSP0136 §3.2.2.3).
ASF_MSG_TYPES: dict[int, str] = {
    0x10: "ASF Reset",
    0x11: "ASF Power-Up",
    0x12: "ASF Power-Cycle Reset",
    0x13: "ASF Power-Down",
    0x14: "ASF Presence Pong",
    0x40: "ASF Presence Pong",
    0x41: "ASF Capabilities Response",
    0x42: "ASF System State Response",
    0x80: "ASF Presence Ping",
    0x81: "ASF Capabilities Request",
    0x82: "ASF System State Request",
    0xC0: "ASF Open Session Request",
    0xC1: "ASF Open Session Response",
    0xC2: "ASF Close Session Request",
    0xC3: "ASF Close Session Response",
}


def lookup_cmd_name(netfn_req: int, cmd: int) -> str:
    """Return command name. OEM registry beats spec table.

    netfn_req must be the *request* NetFn (even). Caller masks LUN/parity.
    Returns "" if not known to either registry.
    """
    from .oem._registry import OEM_CMD_NAMES
    name = OEM_CMD_NAMES.get((netfn_req, cmd))
    if name:
        return name
    return IPMI_CMD_NAMES.get((netfn_req, cmd), "")


def is_oem_netfn(netfn_req: int) -> bool:
    return netfn_req in OEM_NETFNS


def label_from_wire(buf: bytes) -> str:
    """Best-effort label for an RMCP datagram. Returns '' if unparseable.

    Recognises:
      * ASF Ping/Pong and friends (RMCP class 0x06)
      * RMCP+ session-establishment payloads (Open Session, RAKP1-4)
      * IPMI 1.5 and IPMI 2.0 IPMI-Message payloads → cmd name via Table G-1
    For OEM NetFns the label is prefixed with "[OEM] ".
    Unencrypted payloads only — encrypted RMCP+ traffic gets a generic label.
    """
    if len(buf) < 5:
        return ""
    msg_class = buf[3] & 0x1F

    # ASF (DSP0136) — class 0x06.
    if msg_class == 0x06:
        if len(buf) >= 9:
            mt = buf[8]
            return ASF_MSG_TYPES.get(mt, f"ASF msg 0x{mt:02x}")
        return "ASF"

    if msg_class != 0x07:
        return f"RMCP class 0x{msg_class:02x}"

    auth_type = buf[4]

    # IPMI 2.0 RMCP+ session header.
    if auth_type == 0x06:
        if len(buf) < 6:
            return "IPMI 2.0"
        ptype_byte = buf[5]
        ptype = ptype_byte & 0x3F
        encrypted = bool(ptype_byte & 0x80)
        authenticated = bool(ptype_byte & 0x40)
        if ptype != 0x00:
            return RMCP_PAYLOAD_TYPES.get(ptype, f"RMCP+ payload 0x{ptype:02x}")
        # Embedded IPMI message. Header = auth(1)+ptype(1)+sid(4)+seq(4)+len(2) = 12 bytes.
        ipmb_off = 4 + 12
        if encrypted or len(buf) < ipmb_off + 6:
            return "IPMI Message (encrypted)" if encrypted else "IPMI Message"
        netfn = (buf[ipmb_off + 1] >> 2) & 0x3F
        cmd = buf[ipmb_off + 5]
        first_data = buf[ipmb_off + 6] if len(buf) > ipmb_off + 6 else None
        return _cmd_label(netfn, cmd, first_data)

    # IPMI 1.5 session header.
    has_auth_code = auth_type not in (0x00,)
    ipmb_off = 4 + 1 + 4 + 4 + (16 if has_auth_code else 0) + 1
    if len(buf) < ipmb_off + 6:
        return "IPMI"
    netfn = (buf[ipmb_off + 1] >> 2) & 0x3F
    cmd = buf[ipmb_off + 5]
    first_data = buf[ipmb_off + 6] if len(buf) > ipmb_off + 6 else None
    return _cmd_label(netfn, cmd, first_data)


def _cmd_label(netfn: int, cmd: int, first_data: int | None = None) -> str:
    netfn_req = netfn & 0xFE

    # NetFn 0x2C/0x2D = Group Extension. The first data byte is the
    # group code (0xDC=DCMI, 0x00=PICMG, 0x03=VITA, 0x04=HPM). Pull
    # the body-specific name out of GROUP_CMD_NAMES so the trace
    # shows e.g. "DCMI Get Power Reading" instead of generic
    # "Group Extension Request".
    if netfn_req == 0x2C and first_data is not None:
        from .groups._registry import GROUP_CMD_NAMES, GROUP_CODE_TO_NAME
        gname = GROUP_CMD_NAMES.get((first_data, cmd))
        if gname:
            return gname
        body = GROUP_CODE_TO_NAME.get(first_data)
        if body:
            return f"{body} group cmd 0x{cmd:02x}"
        return f"NetFn 0x2C grp 0x{first_data:02x} cmd 0x{cmd:02x}"

    name = lookup_cmd_name(netfn_req, cmd)
    base = name or f"NetFn 0x{netfn_req:02x} cmd 0x{cmd:02x}"
    return f"[OEM] {base}" if is_oem_netfn(netfn_req) else base


__all__ = [
    "IPMI_CMD_NAMES",
    "OEM_NETFNS",
    "RMCP_PAYLOAD_TYPES",
    "ASF_MSG_TYPES",
    "lookup_cmd_name",
    "is_oem_netfn",
    "label_from_wire",
]
