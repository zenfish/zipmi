"""
zipmi.scapy_ipmi.oem.google — Google OpenBMC OEM commands (IANA 11129).

WHAT     The `google-ipmi-sys` provider. Unlike every other OpenBMC OEM
         layer, Google uses the REAL IPMI 2.0 OEM-group wire form:
         NetFn 0x2E (netFnOem), the 3-byte IANA 11129 (LSB-first:
         0x79 0x2B 0x00 — 11129 = 0x2B79), command 0x32, then a 1-byte sub-command from
         enum SysOEMCommands. The sub-command byte is the real dispatch key.

WHY      Google fleets are a distinct OpenBMC flavor. "Get Machine Name"
         (sub 7) and "Get BMC Mode" (sub 16) are strong positive Google
         identifiers; "Accel OOB Read/Write" (sub 13/14) is raw access to
         accelerator devices and "Host Power Off" (sub 10) disables the
         fallback watchdog.

WIRE     Request body: [IANA_LSB(3)] [0x32] [subcmd] [args...]
         zipmi's OEM frame builder supplies the IANA + cmd; callers select
         the operation with the sub-command byte (see GOOGLE_SUBCMDS).

LOAD     `zipmi.load_vendor("google")`

SOURCE   github.com/openbmc/google-ipmi-sys (main.cpp:53 registerOemHandler;
         commands.hpp enum SysOEMCommands). Catalogued in
         /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §2.3.
"""

from __future__ import annotations

from scapy.fields import LEX3BytesField, XByteField
from scapy.packet import Packet

from ._registry import register


GOOGLE_IANA = 11129
GOOGLE_OEM_NETFN = 0x2E
GOOGLE_SYS_CMD = 0x32


# (netfn, cmd) → name. Only one (netfn, cmd) pair exists; the sub-command
# byte (GOOGLE_SUBCMDS) carries the real operation.
GOOGLE_CMD_NAMES: dict[tuple[int, int], str] = {
    (GOOGLE_OEM_NETFN, GOOGLE_SYS_CMD): "Google Sys OEM Command (IANA 11129)",
}


# Sub-command byte → name (enum SysOEMCommands, commands.hpp). All run at
# Privilege::User.
GOOGLE_SUBCMDS: dict[int, str] = {
    0: "Sys Cable Check",
    1: "Sys CPLD Version",
    2: "Sys Get Eth Device",
    3: "Sys PSU Hard Reset",
    4: "Sys PCIe Slot Count",
    5: "Sys PCIe Slot to I2C Bus Mapping",
    6: "Sys Entity Name",
    7: "Sys Machine Name",
    8: "Sys PSU Hard Reset On Shutdown",
    9: "Sys Get Flash Size",
    10: "Sys Host Power Off",
    11: "Accel OOB Device Count",
    12: "Accel OOB Device Name",
    13: "Accel OOB Read",
    14: "Accel OOB Write",
    15: "PCIe Slot Bifurcation",
    16: "Get BMC Mode",
    17: "Linux Boot Done",
    18: "Send Reboot Checkpoint",
    19: "Send Reboot Complete",
    20: "Send Reboot Additional Duration",
    21: "Get Accel VR Settings",
    22: "Set Accel VR Settings",
    23: "Get BM Instance Property",
    24: "Read OEM BIOS Setting",
    25: "Write OEM BIOS Setting",
    30: "Get Core Count",
}


class GoogleSysCommandReq(Packet):
    """Google Sys OEM envelope (NetFn 0x2E, IANA 11129, Cmd 0x32).

    The on-wire request body is the IANA (LSB-first 3 bytes) followed by the
    sub-command byte and its arguments. Build it for a given sub-command:

        bytes(GoogleSysCommandReq(subcmd=7))  # Get Machine Name
    """

    name = "Google Sys OEM Command Request"
    fields_desc = [
        LEX3BytesField("iana", GOOGLE_IANA),
        XByteField("subcmd", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


GOOGLE_PAYLOADS = {
    (GOOGLE_OEM_NETFN, GOOGLE_SYS_CMD): (GoogleSysCommandReq, None),
}


# Vendor detection: "Get Machine Name" (sub 7) returns the build/machine
# name and only Google answers it — the strongest positive Google probe.
GOOGLE_DETECT_PROBE = (GOOGLE_OEM_NETFN, GOOGLE_SYS_CMD, 7)


register("google", GOOGLE_IANA, GOOGLE_CMD_NAMES, GOOGLE_PAYLOADS)


__all__ = [
    "GOOGLE_IANA",
    "GOOGLE_OEM_NETFN",
    "GOOGLE_SYS_CMD",
    "GOOGLE_CMD_NAMES",
    "GOOGLE_SUBCMDS",
    "GOOGLE_PAYLOADS",
    "GOOGLE_DETECT_PROBE",
]
