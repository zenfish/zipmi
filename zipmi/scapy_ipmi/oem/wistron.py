"""
zipmi.scapy_ipmi.oem.wistron — Wistron OpenBMC OEM commands.

WHAT     The `wistron-ipmi-oem` provider. Two OEM commands on NetFn 0x30
         (NETFUN_OEM) at SYSTEM_INTERFACE privilege: Detect Riser-F
         (0x30/0x01, an I2C/SMBus riser probe) and Switch Bittware Image
         (0x30/0x02, an FPGA/accelerator image switch).

WIRE     Raw NetFn 0x30 (NETFUN_OEM value is from-memory — the standard
         ipmid 0x30). No IANA on the wire — passed as None to the registry.

NOTE     NetFn 0x30 is the busiest vendor band; 0x30/0x01 also means "Get BMC
         Version String" under Intel. Load exactly the vendor you target.

LOAD     `zipmi.load_vendor("wistron")`

SOURCE   github.com/openbmc/wistron-ipmi-oem (wistronoem.cpp:126,
         IPMI_CMD_DETECT_RISERF=0x01, IPMI_CMD_SWITCH_BITTWARE_IMAGE=0x02).
         Catalogued in /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md §2.8.
"""

from __future__ import annotations

from ._registry import register


WISTRON_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x30, 0x01): "Wistron Detect Riser-F",
    (0x30, 0x02): "Wistron Switch Bittware Image",
}


register("wistron", None, WISTRON_CMD_NAMES)


__all__ = ["WISTRON_CMD_NAMES"]
