#!/usr/bin/env python3
"""ipmi_firewall.py — enumerate & interpret the IPMI Firmware Firewall discovery.

WHAT   Walks the IPMI 2.0 "Firmware Firewall Configuration" discovery commands
       (NetFn App 0x06) against a live BMC and interprets the result:

         0x09 Get NetFn Support            -> which NetFns the channel exposes
         0x0A Get Command Support          -> per-NetFn, which commands the
                                              firewall CAN control (NOT the same
                                              as "implemented" — see note)
         0x0B Get Configurable Commands    -> which of those can be disabled
         0x0C Get Command Sub-function Support (for group-extension NetFns)
         0x62 Get Command Enables          -> current enable state (on/off)

       Each command is resolved to a human name via zipmi's IPMI_CMD_NAMES /
       OEM catalogs. With --probe it also sends each command (empty body) to
       ground-truth "implemented" (cc != 0xC1) vs merely "firewall-tracked".

WHY    A BMC's firewall tables are the machine-readable map of its command
       surface. The support mask is what the vendor chose to make firewall-
       controllable; mandatory commands (Get Device ID, the firewall cmds
       themselves) are implemented but NOT in the support mask. Reading the
       masks + cross-probing separates "exposed & lockable", "exposed &
       fixed", and "not present" — the picture you want before an audit.

USAGE  python3 scripts/ipmi_firewall.py -H 127.0.0.1 -p 5623 -C 17 \
              -U admin -P superuser [--channel 0x0e] [--probe] [--json out.json]

NOTE   Bit semantics (IPMI 2.0 §21.4): Get Command Support returns a 16-byte
       (128-bit) mask, bit N (LSB-first) = command N. 1b there means the
       firewall *supports controlling* that command — a superset-ish of
       "configurable", a subset of "implemented". We label each accordingly.
"""
from __future__ import annotations

import argparse
import json
import sys

from zipmi.cli.zipmi import _open_session, AUTH_BY_NAME
from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name

CC_INVALID_CMD = 0xC1          # command not implemented for this NetFn/LUN
CC_INSUFFICIENT_PRIV = 0xD4
NETFN_NAMES = {
    0x00: "Chassis", 0x02: "Bridge", 0x04: "Sensor/Event", 0x06: "App",
    0x08: "Firmware", 0x0A: "Storage", 0x0C: "Transport",
    0x2C: "Group-Ext (DCMI/HPM)", 0x2E: "OEM-Group (IANA)",
    0x30: "OEM (AMI 0x30)", 0x32: "OEM/WCS 0x32", 0x34: "OEM 0x34",
    0x36: "OEM/WCS 0x36", 0x38: "OEM/WCS 0x38", 0x3A: "OEM 0x3A",
    0x3C: "OEM 0x3C", 0x3E: "OEM (AMI 0x3E)",
}


def _bits(mask: bytes) -> list[int]:
    """Return the command codes whose bit is set (LSB-first, byte0 bit0 = cmd0)."""
    return [i * 8 + b for i, byte in enumerate(mask) for b in range(8) if byte >> b & 1]


def get_netfn_support(s, channel: int) -> list[int]:
    """0x06/0x09 -> list of supported request NetFns (even codes 0x00..0x3E)."""
    cc, d = s.send_raw(0x06, 0x09, bytes([channel]))
    if cc != 0 or len(d) < 2:
        return []
    # response: [reserved byte0][NetFn-pair bitmask...]; pair i => NetFn 2*i
    mask = d[1:]
    return [2 * (i * 8 + b) for i, byte in enumerate(mask) for b in range(8) if byte >> b & 1]


def get_cmd_mask(s, cmd: int, channel: int, netfn: int, lun: int = 0):
    """Generic per-NetFn 16-byte-mask query (0x0A support / 0x0B configurable)."""
    cc, d = s.send_raw(0x06, cmd, bytes([channel, netfn, lun]))
    if cc != 0 or len(d) < 16:
        return None
    return d[:16]


def get_cmd_enables(s, channel: int, netfn: int, lun: int = 0):
    """0x06/0x62 Get Command Enables -> 16-byte mask, bit=1 => command enabled."""
    cc, d = s.send_raw(0x06, 0x62, bytes([channel, netfn, lun]))
    if cc != 0 or len(d) < 16:
        return None
    return d[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="Enumerate + interpret the IPMI firmware firewall")
    ap.add_argument("-H", "--host", required=True)
    ap.add_argument("-p", "--port", type=int, default=623)
    ap.add_argument("-U", "--user")
    ap.add_argument("-P", "--password")
    ap.add_argument("-C", "--cipher", type=int, default=17)
    ap.add_argument("-t", "--timeout", type=float, default=6.0)
    ap.add_argument("--channel", default="0x0e",
                    help="channel to query (default 0x0e = current)")
    ap.add_argument("--probe", action="store_true",
                    help="also send each firewall-tracked command (empty body) to "
                         "ground-truth implemented (cc!=0xC1). Side-effecty — vbmc only.")
    ap.add_argument("--json", metavar="FILE", help="write structured result to FILE")
    a = ap.parse_args()
    channel = int(a.channel, 0)

    ns = argparse.Namespace(
        host=a.host, port=a.port, user=a.user, password=a.password, key=None,
        auth="none", interface="lanplus", cipher=a.cipher, timeout=a.timeout,
        verbose=False, debug=False, no_color=True, palette=None)

    result = {"host": a.host, "port": a.port, "channel": channel, "netfns": {}}
    with _open_session(ns) as s:
        netfns = get_netfn_support(s, channel)
        print(f"# IPMI Firmware Firewall — {a.host}:{a.port} channel {channel:#04x}")
        print(f"# Supported NetFns (Get NetFn Support 0x09): "
              + ", ".join(f"{n:#04x}({NETFN_NAMES.get(n,'?')})" for n in netfns) + "\n")

        for nf in netfns:
            support = get_cmd_mask(s, 0x0A, channel, nf)
            if support is None:
                continue
            configurable = get_cmd_mask(s, 0x0B, channel, nf) or b"\x00" * 16
            enables = get_cmd_enables(s, channel, nf) or b"\xff" * 16
            sup = set(_bits(support)); cfg = set(_bits(configurable)); en = set(_bits(enables))
            nfname = NETFN_NAMES.get(nf, f"NetFn {nf:#04x}")
            # MegaRAC (and others) default the whole 0-127 firewall table to
            # supported, so the raw mask is coarse. Split into commands with a
            # known IPMI/OEM name (trustworthy) vs unnamed set-bits (mostly the
            # over-reported reserved codes — use --probe for ground truth).
            named = [c for c in sorted(sup) if lookup_cmd_name(nf, c)]
            unnamed = [c for c in sorted(sup) if not lookup_cmd_name(nf, c)]
            disabled = sorted(sup - en)                      # firewall-blocked commands
            coarse = " [mask coarse: firewall defaults reserved codes to supported]" if len(sup) > 40 else ""
            print(f"NetFn {nf:#04x}  {nfname}  — {len(sup)} in firewall table, "
                  f"{len(named)} named, {len(disabled)} DISABLED{coarse}")
            rows = []
            if nf >= 0x2E and not named:
                # OEM range with no name catalog: the mask is all-defaulted, so
                # don't spam 128 <OEM> lines — the real command↔handler map is the
                # per-.so registration tables (see the firmware's libipmiamioem*.so).
                print(f"    {len(sup)} OEM command slots (no name catalog; map opcodes to the "
                      f"libipmiamioem*.so handler tables). {len(disabled)} disabled.")
                for c in sorted(sup):
                    rows.append({"cmd": c, "name": "<OEM>", "configurable": c in cfg, "enabled": c in en})
                result["netfns"][f"0x{nf:02x}"] = {"name": nfname, "named": 0,
                                                   "total_in_table": len(sup), "disabled": disabled,
                                                   "commands": rows}
                print()
                continue
            show = named
            for c in show:
                name = lookup_cmd_name(nf, c) or ("<OEM>" if nf >= 0x2E else "<reserved>")
                flags = ("configurable" if c in cfg else "fixed",
                         "enabled" if c in en else "DISABLED")
                impl = ""
                if a.probe:
                    cc, _ = s.send_raw(nf, c)
                    impl = " impl" if cc != CC_INVALID_CMD else " not-impl"
                mark = "  <-- blocked" if c not in en else ""
                print(f"    0x{c:02x}  {name:<34s} [{', '.join(flags)}]{impl}{mark}")
                rows.append({"cmd": c, "name": name, "configurable": c in cfg,
                             "enabled": c in en, **({"implemented": impl.strip()} if a.probe else {})})
            if named and unnamed and nf < 0x2E:
                print(f"    + {len(unnamed)} unnamed set-bits (reserved codes the firewall over-reports; --probe to confirm)")
            result["netfns"][f"0x{nf:02x}"] = {"name": nfname, "named": len(named),
                                               "total_in_table": len(sup), "disabled": disabled,
                                               "commands": rows}
            print()

    if a.json:
        json.dump(result, open(a.json, "w"), indent=2)
        print(f"# wrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
