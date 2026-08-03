"""
zipmi.scapy_ipmi.oem.inspur — Inspur OpenBMC OEM commands.

WHAT     The `inspur-ipmi-oem` provider. One OEM command on raw NetFn 0x3C:
         OEM Asset Info (0x3C/0x01), an asset/inventory string.

WIRE     Raw NetFn 0x3C. COLLIDES with Ampere (also raw 0x3C) — on the wire
         0x3C/0x01 is Inspur "Asset Info" OR Ampere "Edit BMC MAC" depending
         on the platform. Load exactly the vendor you target.

LOAD     `zipmi.load_vendor("inspur")`

SOURCE   github.com/openbmc/inspur-ipmi-oem (src/inspur_oem.cpp:175,
         NETFN_OEM_INSPUR=0x3C, CMD_OEM_ASSET_INFO=0x01). IANA 37945 is
         from-memory (not on the wire). Catalogued in
         the OpenBMC OEM IPMI survey (upstream source review) §2.6.
"""

from __future__ import annotations

from ._registry import register


INSPUR_IANA = 37945  # from-memory; not on the wire

INSPUR_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x3C, 0x01): "Inspur OEM Asset Info",
}


register("inspur", INSPUR_IANA, INSPUR_CMD_NAMES)


__all__ = ["INSPUR_IANA", "INSPUR_CMD_NAMES"]
