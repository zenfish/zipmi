"""
zipmi.scapy_ipmi.groups.sbmr — SBMR boot-progress group (group code 0xAE).

WHAT     The ARM Server Base Manageability Requirements (SBMR) boot-progress
         group-extension commands. NetFn 0x2C request / 0x2D response, group
         code 0xAE ("groupSBMR"). Two commands: Send and Get Boot Progress
         Code (the host pushes EFI/boot status codes to the BMC).

WHY      SBMR boot-progress is how ARM OpenBMC platforms (Ampere, Nvidia
         Grace, and other aarch64 builds with ARM_SBMR_SUPPORT) report host
         firmware boot phase. Presence of group 0xAE is a useful fingerprint
         that a BMC is an ARM OpenBMC build, and Get Boot Progress Code
         (0xAE/0x03) leaks the host's current boot phase pre-auth-permitting.

SUCCESS  After import, GROUP_CMD_NAMES[(0xAE, 0x03)] ==
         "SBMR Get Boot Progress Code".

SOURCE   github.com/openbmc/phosphor-host-ipmid sbmrhandler.cpp:305
         (groupExtIpmi=0xAE); also ampere-ipmi-oem bootprogress.cpp.
         Catalogued in /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §0,§2.4.
"""

from __future__ import annotations

from ._registry import register


SBMR_GROUP_CODE = 0xAE

SBMR_CMD_NAMES: dict[tuple[int, int], str] = {
    (0xAE, 0x02): "SBMR Send Boot Progress Code",
    (0xAE, 0x03): "SBMR Get Boot Progress Code",
}


register("sbmr", SBMR_GROUP_CODE, SBMR_CMD_NAMES)


__all__ = ["SBMR_GROUP_CODE", "SBMR_CMD_NAMES"]
