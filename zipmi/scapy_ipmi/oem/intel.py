"""
zipmi.scapy_ipmi.oem.intel — Intel OpenBMC OEM commands (IANA 343).

WHAT     Command-name table for the `intel-ipmi-oem` provider that ships on
         Intel server-board OpenBMC builds (the largest OEM surface in the
         OpenBMC ecosystem). Covers the pure-OEM vendor NetFns
         0x30 (General), 0x32 (Platform), 0x3E (App) and the OEM firmware-
         update state machine that overrides NetFn 0x08.

WHY      Intel boards are the most-seen identifiable OpenBMC flavor in our
         internet survey (see /Users/zen/phd/bmc/openbmc/SURVEY-OPENBMC.md).
         Several commands are directly attack-relevant: Set Special User
         Password (0x30/0x5F), Control BMC Services (0x30/0xB1), the
         manufacturing-mode unlocks (0x30/0xA4,0xB5), Get BIOS Password Hash
         (0x30/0xD8) and the raw firmware-write path (0x08/0x2C).

WIRE     intel-ipmi-oem uses RAW vendor NetFns — it does NOT put IANA 343 on
         the wire. The IANA here is metadata for the zipmi vendor key only;
         do not build a NetFn 0x2E IANA frame for these commands.

LOAD     `zipmi.load_vendor("intel")`

SOURCE   github.com/openbmc/intel-ipmi-oem (catalogued from source in
         /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §2.1).
         netFnGeneral=0x30, netFnPlatform=0x32, netFnApp=0x3E
         (include/oemcommands.hpp).
"""

from __future__ import annotations

from scapy.fields import ByteEnumField, LEX3BytesField, XByteField
from scapy.packet import Packet

from ..commands import COMP_CODE
from ._registry import register


INTEL_IANA = 343


# --- pure-OEM vendor-NetFn commands --------------------------------------

INTEL_GENERAL = 0x30   # netFnGeneral
INTEL_PLATFORM = 0x32  # netFnPlatform
INTEL_APP = 0x3E       # netFnApp
INTEL_FIRMWARE = 0x08  # standard Firmware NetFn, overridden by Intel OEM block

INTEL_CMD_NAMES: dict[tuple[int, int], str] = {
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
    (0x30, 0xB5): "Intel MTM Keep Alive",
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
}


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
}


# Probe used by vendor detection: harmless User-priv read that only Intel
# answers (returns the BMC version string). A non-0xC1 completion code means
# the intel-ipmi-oem provider is present.
INTEL_DETECT_PROBE = (0x30, 0x01)


register("intel", INTEL_IANA, INTEL_CMD_NAMES, INTEL_PAYLOADS)


__all__ = [
    "INTEL_IANA",
    "INTEL_CMD_NAMES",
    "INTEL_PAYLOADS",
    "INTEL_DETECT_PROBE",
]
