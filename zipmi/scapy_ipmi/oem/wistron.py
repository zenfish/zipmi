"""
zipmi.scapy_ipmi.oem.wistron — Wistron OpenBMC OEM commands.

WHAT     The `wistron-ipmi-oem` provider. Two OEM commands on NetFn 0x32
         (NETFUN_OEM) at SYSTEM_INTERFACE privilege: Detect Riser-F
         (0x32/0x01, an I2C/SMBus riser probe) and Switch Bittware Image
         (0x32/0x02, an FPGA flash-bank-select via `gpioset`).

WIRE     Raw NetFn 0x32. `NETFUN_OEM` resolves to 0x32 — confirmed from
         phosphor-host-ipmid `include/ipmid/api.h:98` (`NETFUN_OEM = 0x32`),
         not the 0x30 a guess would suggest. No IANA on the wire (None).

NOTE     NetFn 0x32 (netFnOemTwo) is also used by Intel (Clear CMOS) and
         IBM/OpenPOWER (Prep FW Update) — load exactly the vendor you target.

LOAD     `zipmi.load_vendor("wistron")`

SOURCE   github.com/openbmc/wistron-ipmi-oem (wistronoem.cpp:126
         `ipmi_register_callback(NETFUN_OEM, ...)`,
         IPMI_CMD_DETECT_RISERF=0x01, IPMI_CMD_SWITCH_BITTWARE_IMAGE=0x02);
         NETFUN_OEM from phosphor api.h:98.
"""

from __future__ import annotations

from ._registry import register


WISTRON_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x32, 0x01): "Wistron Detect Riser-F",
    (0x32, 0x02): "Wistron Switch Bittware Image",
}


register("wistron", None, WISTRON_CMD_NAMES)


__all__ = ["WISTRON_CMD_NAMES"]
