"""
zipmi.scapy_ipmi.oem.ampere — Ampere OpenBMC OEM commands (IANA 40981).

WHAT     The `ampere-ipmi-oem` provider for Ampere Altra / Mt.* platforms.
         Commands ride raw vendor NetFn 0x3C (netFnAmpere). Ampere also
         registers two SBMR boot-progress commands under the 0xAE group —
         those live in the group registry (see groups/sbmr.py), loaded
         separately.

WHY      Ampere is an ARM (aarch64) OpenBMC flavor. Several commands are
         raw SoC access: SCP Read/Write Register Map (0x3C/0x17,0x18),
         Configure UART Switch (0x3C/0xB0 — console mux), Edit BMC MAC
         (0x3C/0x01), and Set Scandump Mode (0x3C/0x25 — debug).

WIRE     Raw NetFn 0x3C, no IANA on the wire. IANA 40981 is the zipmi
         vendor key only.

NOTE     NetFn 0x3C COLLIDES on the wire with Inspur (also raw 0x3C) and is
         distinct from Nvidia's group-0x3C (which is under NetFn 0x2C). Same
         (netfn,cmd) means different things per vendor — load exactly the
         vendor you are targeting.

LOAD     `zipmi.load_vendor("ampere")`

SOURCE   github.com/openbmc/ampere-ipmi-oem (include/oemcommands.hpp:103
         netFnAmpere=0x3C; src/oemcommands.cpp). Catalogued in
         /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §2.4.
"""

from __future__ import annotations

from ._registry import register


# PROVENANCE: upstream github.com/openbmc/ampere-ipmi-oem registers only TWO
# OEM commands — Edit BMC MAC (0x3C/0x01) and Sync RTC (0x3C/0xF9). The richer
# set below (SCP register R/W, scandump, SoC power-limit, UART switch, ...)
# comes from the DOWNSTREAM Ampere Altra vendor fork (vendored as
# OEM/ampere-ipmi-oem in the openbmc tree) — real on Altra hardware, but not
# in the upstream repo. Kept here because Altra systems are the live targets.
AMPERE_IANA = 40981
AMPERE_NETFN = 0x3C

AMPERE_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x3C, 0x01): "Ampere Edit BMC MAC Address",
    (0x3C, 0x02): "Ampere Get Fan Control Status",
    (0x3C, 0x03): "Ampere Set Fan Control Status",
    (0x3C, 0x04): "Ampere Set Fan Speed",
    (0x3C, 0x11): "Ampere Set SoC Power Limit",
    (0x3C, 0x12): "Ampere Get SoC Power Limit",
    (0x3C, 0x15): "Ampere Trigger Host FW Crash Dump",
    (0x3C, 0x17): "Ampere SCP Read Register Map",
    (0x3C, 0x18): "Ampere SCP Write Register Map",
    (0x3C, 0x1E): "Ampere Set DRAM Max Throttle Enable",
    (0x3C, 0x1F): "Ampere Get DRAM Max Throttle Enable",
    (0x3C, 0x25): "Ampere Set Scandump Mode",
    (0x3C, 0x26): "Ampere Get Scandump Mode",
    (0x3C, 0x27): "Ampere Set Ext Vref",
    (0x3C, 0xB0): "Ampere Configure UART Switch",
    (0x3C, 0xF0): "Ampere Set Host FW Revision",
    (0x3C, 0xF6): "Ampere Set FW Inband Update Status",
    (0x3C, 0xF9): "Ampere Sync RTC Time To BMC",
}


# Vendor detection: "Get Fan Control Status" is a harmless User read that
# only Ampere answers on NetFn 0x3C.
AMPERE_DETECT_PROBE = (0x3C, 0x02)


register("ampere", AMPERE_IANA, AMPERE_CMD_NAMES)


__all__ = ["AMPERE_IANA", "AMPERE_NETFN", "AMPERE_CMD_NAMES", "AMPERE_DETECT_PROBE"]
