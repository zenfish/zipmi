"""
zipmi.scapy_ipmi.oem.nvidia — Nvidia OpenBMC OEM commands (group 0x3C).

WHAT     Nvidia's OEM commands ship inside phosphor-host-ipmid's
         `oem/nvidia` and are registered as a GROUP EXTENSION, not an IANA
         OEM block: wire NetFn 0x2C, group byte 0x3C (groupNvidia), then the
         command byte. So although this module lives under oem/ for
         load_vendor() convenience, it populates the GROUP registry
         (keys are (group_code, cmd)), not OEM_CMD_NAMES.

WHY      Bootstrap-credential and BIOS-password commands: Get Redfish Host
         Name (0x3C/0x32), Get Redfish Service UUID (0x3C/0x34), and
         Set/Get BIOS Password (0x3C/0x36,0x37). All Admin privilege.

NOTE     group 0x3C (under NetFn 0x2C) is DISTINCT from Ampere/Inspur's raw
         NetFn 0x3C. Different wire NetFn (0x2C vs 0x3C) — they do not
         collide. This module is opt-in (not auto-loaded) because reusing a
         group code as 0x3C is non-standard and Nvidia-specific.

LOAD     `zipmi.load_vendor("nvidia")`

SOURCE   github.com/openbmc/phosphor-host-ipmid oem/nvidia
         (bootstrap-credentials-oem-cmds.cpp:199, biosconfigcommands.cpp:182;
         groupNvidia=0x3C). Catalogued in
         /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §2.9.
"""

from __future__ import annotations

from ..groups._registry import register as register_group


NVIDIA_GROUP_CODE = 0x3C  # groupNvidia, under NetFn 0x2C

NVIDIA_GROUP_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x3C, 0x30): "Nvidia Get USB Vendor/Product ID",
    (0x3C, 0x31): "Nvidia Get USB Serial Number",
    (0x3C, 0x32): "Nvidia Get Redfish Host Name",
    (0x3C, 0x33): "Nvidia Get IPMI Channel for Redfish-HI",
    (0x3C, 0x34): "Nvidia Get Redfish Service UUID",
    (0x3C, 0x35): "Nvidia Get Redfish Service Port",
    (0x3C, 0x36): "Nvidia Set BIOS Password",
    (0x3C, 0x37): "Nvidia Get BIOS Password",
}


register_group("nvidia", NVIDIA_GROUP_CODE, NVIDIA_GROUP_CMD_NAMES)


__all__ = ["NVIDIA_GROUP_CODE", "NVIDIA_GROUP_CMD_NAMES"]
