#!/usr/bin/env python3
"""
03_sol_info.py — read Serial-Over-LAN config (bit rate detection).

WHAT     Opens an authenticated session, reads the SOL volatile bit-rate
         parameter (selector 6, falling back to non-volatile 5), and
         prints the live console baud rate. This is the number a
         PXE/serial boot needs for `console=ttyS1,<baud>`.

WHY      BMC SOL defaults vary (iDRAC6 = 19200, most others = 115200).
         Guessing wrong makes post-BIOS console output garbage. Reading
         it removes the guesswork. See docs/sol-baud-detect.md.

SUCCESS  Against Dell iDRAC6 (192.168.0.23):
            $ ZIPMI_USER=root ZIPMI_PASS=calvin \
                  python examples/03_sol_info.py 192.168.0.23
            SOL volatile bit rate : 19200 baud
            (matches `ipmitool sol info` "Volatile Bit Rate (kbps): 19.2")

TARGET   IPMI 2.0 §26.3 (SOL config) / §15. Dell iDRAC6 verified.
RUN      python examples/03_sol_info.py <bmc-ip> [-U user] [-P pass]
            [--lanplus] [-C cipher]
EXIT     0 on success; 1 on IPMI/transport error.
RELATED  zipmi/scapy_ipmi/commands.py (decode_sol_bitrate), zipmi/core.py
"""

from __future__ import annotations

import argparse
import os
import sys

from zipmi.core import AUTH_MD5, IPMIError, Session
from zipmi.scapy_ipmi.commands import decode_sol_bitrate


def sol_bit_rate(s: Session, channel: int = 0x0E) -> int | None:
    """Return live SOL baud (int) or None. Volatile (6) then non-volatile (5)."""
    for sel in (6, 5):
        cc, data = s.send_raw(0x0C, 0x22, bytes([channel, sel, 0, 0]))
        if cc == 0 and len(data) >= 2:          # data = [param_rev, bitrate_byte]
            baud = decode_sol_bitrate(data[1])
            if baud:
                return baud
    return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("host")
    p.add_argument("-U", "--user", default=os.environ.get("ZIPMI_USER", "root"))
    p.add_argument("-P", "--password", default=os.environ.get("ZIPMI_PASS", "calvin"))
    p.add_argument("-t", "--timeout", type=float, default=3.0)
    p.add_argument("--lanplus", action="store_true", help="use IPMI 2.0 RMCP+")
    p.add_argument("-C", "--cipher", type=int, default=3)
    args = p.parse_args(argv[1:])

    try:
        with Session(
            host=args.host, username=args.user, password=args.password,
            auth_type=AUTH_MD5, timeout=args.timeout,
            lanplus=args.lanplus, cipher_suite=args.cipher,
        ) as s:
            baud = sol_bit_rate(s)
    except IPMIError as e:
        print(f"IPMI error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"transport error: {e}", file=sys.stderr)
        return 1

    if baud is None:
        print("could not read SOL bit rate", file=sys.stderr)
        return 1
    print(f"SOL volatile bit rate : {baud} baud")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
