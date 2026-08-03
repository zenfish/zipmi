"""
zipmi.scapy_ipmi.oem.foxconn — Foxconn (fii/kudo) OpenBMC OEM commands.

WHAT     The `foxconn-ipmi-oem` provider. Two OEM reads on raw NetFn 0x34
         (netFnOemThree): Get System PCIe Info (0x34/0x03) and Get BIOS Boot
         Count (0x34/0x71).

WIRE     Raw NetFn 0x34, no IANA on the wire. Foxconn's enterprise number is
         not used here — passed as None to the registry.

LOAD     `zipmi.load_vendor("foxconn")`

SOURCE   github.com/openbmc/foxconn-ipmi-oem (src/systemcommands.cpp:73,
         src/bioscommands.cpp:104). Catalogued in
         the OpenBMC OEM IPMI survey (upstream source review) §2.7.
"""

from __future__ import annotations

from ._registry import register


FOXCONN_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x34, 0x03): "Foxconn Get System PCIe Info",
    (0x34, 0x71): "Foxconn Get BIOS Boot Count",
}


register("foxconn", None, FOXCONN_CMD_NAMES)


__all__ = ["FOXCONN_CMD_NAMES"]
