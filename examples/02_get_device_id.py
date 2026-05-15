#!/usr/bin/env python3
"""
02_get_device_id.py — authenticated IPMI 1.5 session demo.

WHAT     Opens an MD5-authenticated IPMI 1.5 LAN session, sends
         Get Device ID and Get Chassis Status, prints decoded results,
         and closes the session.

WHY      End-to-end exercise of the full activation flow: Get Channel
         Auth Caps -> Get Session Challenge -> Activate Session ->
         Set Session Privilege Level -> command -> Close Session.
         Equivalent to `ipmitool -I lan -A MD5 mc info` plus
         `chassis status`.

SUCCESS  Against Dell iDRAC6 (192.168.0.23):
            $ ZIPMI_USER=root ZIPMI_PASS=calvin python examples/02_get_device_id.py 192.168.0.23
            mc      manuf=674 (Dell)  fw=1.70  ipmi_ver=0x51 product=0x0100
            chassis power=on  last_event=0x..  state=0x..

TARGET   IPMI 1.5 LAN, MD5 auth. Dell iDRAC6 / FW 1.70.
RUN      python examples/02_get_device_id.py <bmc-ip> [-U user] [-P pass]
EXIT     0 on success; 1 on any IPMI/transport error; 2 on usage error.
RELATED  zipmi/core.py, zipmi/scapy_ipmi/commands.py
"""

from __future__ import annotations

import argparse
import os
import sys

from zipmi.consts import IANA
from zipmi.core import AUTH_MD5, IPMIError, Session


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("host", help="BMC IP address")
    p.add_argument("-U", "--user", default=os.environ.get("ZIPMI_USER", "root"))
    p.add_argument("-P", "--password", default=os.environ.get("ZIPMI_PASS", "calvin"))
    p.add_argument("-t", "--timeout", type=float, default=3.0)
    args = p.parse_args(argv[1:])

    try:
        with Session(
            host=args.host,
            username=args.user,
            password=args.password,
            auth_type=AUTH_MD5,
            timeout=args.timeout,
        ) as s:
            dev = s.get_device_id()
            chassis = s.get_chassis_status()
    except IPMIError as e:
        print(f"IPMI error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"transport error: {e}", file=sys.stderr)
        return 1

    manuf = dev.manufacturer_id_int()
    print(
        f"mc      manuf={manuf} ({IANA.get(manuf, 'unknown')})  "
        f"fw={dev.fw_revision()}  "
        f"ipmi_ver=0x{dev.ipmi_version:02x}  "
        f"product=0x{dev.product_id:04x}"
    )
    print(
        f"chassis power={'on' if chassis.power_on() else 'off'}  "
        f"last_event=0x{chassis.last_power_event:02x}  "
        f"state=0x{chassis.misc_chassis_state:02x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
