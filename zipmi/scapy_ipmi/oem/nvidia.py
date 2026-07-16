"""
zipmi.scapy_ipmi.oem.nvidia — Nvidia OpenBMC OEM commands (raw NetFn 0x3C).

WHAT     Nvidia's OEM commands ship inside phosphor-host-ipmid's `oem/nvidia`.
         Despite the constant being named `groupNvidia`, they are registered
         with `ipmi::registerHandler(prioOemBase, groupNvidia, cmd, ...)` —
         i.e. `groupNvidia = 0x3C` is passed in the **NetFn** position, so
         these are RAW NetFn 0x3C commands, NOT a NetFn 0x2C group extension.
         (registerHandler keys on (NetFn, cmd); registerGroupHandler would be
         the 0x2C group form, and Nvidia does not use it.)

WHY      Bootstrap-credential + BIOS-password commands: Get Redfish Host Name
         (0x3C/0x32), Get Redfish Service UUID (0x3C/0x34), Set/Get BIOS
         Password (0x3C/0x36,0x37). All Admin privilege.

WIRE     Raw NetFn 0x3C — COLLIDES with Ampere and Inspur (both raw 0x3C).
         Nvidia uses cmd bytes 0x30–0x37, which don't overlap Ampere's or
         Inspur's cmd bytes, but you should still load exactly the vendor you
         target. No IANA on the wire (registered None).

LOAD     `zipmi.load_vendor("nvidia")`

SOURCE   github.com/openbmc/phosphor-host-ipmid oem/nvidia
         (bootstrap-credentials-oem-cmds.cpp:199 `registerHandler(prioOemBase,
         groupNvidia, ...)`; oemcommands.hpp:13 `constexpr Group groupNvidia
         = 0x3C`). Verified 2026-06 against fresh upstream — corrects an
         earlier mis-modeling as a 0x2C group extension.
"""

from __future__ import annotations

from ._registry import register


NVIDIA_NETFN = 0x3C  # groupNvidia, used as a raw NetFn

# Keys are (NetFn, Cmd[, fixed-prefix-bytes]). A 3rd+ element is a fixed
# request-data prefix the CLI auto-supplies (see cli/oem_cmds.py dispatch), so
# the user never types a mandatory selector. BIOS Get/Set only accept password
# selector id=0x01 (admin) — the handler rejects anything else with 0xC9 — so
# 0x01 is baked in: `ob-nvidia get-bios-password` needs no data; set adds only
# the variable type+salt+hash after it.
NVIDIA_CMD_NAMES: dict[tuple[int, ...], str] = {
    (0x3C, 0x30): "Nvidia Get USB Vendor/Product ID",  # + type byte (1=VID, 2=PID)
    (0x3C, 0x31): "Nvidia Get USB Serial Number",
    (0x3C, 0x32): "Nvidia Get Redfish Host Name",
    (0x3C, 0x33): "Nvidia Get IPMI Channel for Redfish-HI",
    (0x3C, 0x34): "Nvidia Get Redfish Service UUID",
    (0x3C, 0x35): "Nvidia Get Redfish Service Port",
    (0x3C, 0x36, 0x01): "Nvidia Set BIOS Password",  # id=0x01; + type+salt[32]+hash[64]
    (0x3C, 0x37, 0x01): "Nvidia Get BIOS Password",  # id=0x01; no further data
}


# Vendor detection: Get Redfish Service UUID (0x3C/0x34) is a harmless read.
NVIDIA_DETECT_PROBE = (0x3C, 0x34)


register("nvidia", None, NVIDIA_CMD_NAMES)


__all__ = ["NVIDIA_NETFN", "NVIDIA_CMD_NAMES", "NVIDIA_DETECT_PROBE"]
