"""
zipmi.scapy_ipmi.oem.openpower — IBM / OpenPOWER OpenBMC OEM commands (IANA 2).

WHAT     The `openpower-host-ipmi-oem` provider used on IBM POWER reference
         systems (Romulus, Witherspoon, Rainier, ...). A small set of OEM
         commands on raw NetFns 0x32 and 0x3A, registered at
         SYSTEM_INTERFACE privilege via the legacy ipmi_register_callback.

WHY      This is the flavor on our local QEMU `romulus` target
         (ID=openbmc-openpower). BMC Factory Reset (0x3A/0x11) is
         destructive; Prep FW Update (0x32/0x10) is the firmware-update
         entry point; Partial Add eSEL (0x3A/0xF0) injects platform error
         logs.

WIRE     Raw NetFns 0x32/0x3A, no IANA on the wire. IBM's enterprise number
         is 2; note the local romulus reports Get Device ID manufacturer-id
         = 0 (Unknown) anyway, so IPMI alone cannot confirm IBM — read
         /etc/os-release or Redfish Oem.OpenBmc (see LIVE-QEMU-romulus.md).

LOAD     `zipmi.load_vendor("openpower")`  (alias: "ibm")

SOURCE   github.com/openbmc/openpower-host-ipmi-oem (oemhandler.cpp:451).
         Catalogued in the OpenBMC OEM IPMI survey (upstream source review) §2.5.
"""

from __future__ import annotations

from ._registry import register


OPENPOWER_IANA = 2  # IBM

OPENPOWER_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x32, 0x10): "OpenPower Prep FW Update",
    (0x3A, 0x11): "OpenPower BMC Factory Reset",
    (0x3A, 0xF0): "OpenPower Partial Add eSEL",
}


register("openpower", OPENPOWER_IANA, OPENPOWER_CMD_NAMES)


__all__ = ["OPENPOWER_IANA", "OPENPOWER_CMD_NAMES"]
