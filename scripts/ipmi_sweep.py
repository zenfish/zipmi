#!/usr/bin/env python3
"""ipmi_sweep.py — walk zipmi's STANDARD IPMI command catalog against a live
BMC and record (cc, response) for each, keyed by BMC version.

WHAT     Sibling of scripts/oem_sweep.py, but for the spec commands in
         IPMI_CMD_NAMES (Chassis/Bridge/Sensor/App/Storage/Transport netfns)
         rather than a single vendor's OEM table. Two modes:

           authenticated (default) — open one lanplus session and fire every
             catalogued (NetFn,Cmd) via Session.send_raw; record cc + bytes.

           --sessionless — no creds; send each command straight over
             Transport.sessionless_request in BOTH framings (IPMI 1.5 and
             RMCP+) and record which framing the BMC answers. This is the
             diagnostic that catches the iDRAC10 class of bug: a 2.0-only
             command (e.g. Get Channel Cipher Suites 0x54) that answers under
             RMCP+ but times out under 1.5 framing shows up as an asymmetry in
             the map.

WHY      1. Per-firmware support/framing matrix — run against idrac9 vs
            idrac10 vs a Supermicro X14 and diff to see exactly what each
            version answers and in which framing. Regressions in what we send
            or how we decode surface as a JSON diff.
         2. Golden fixtures the vbmc can replay (see zipmi/vbmc), same as
            oem_sweep's captures.

SAFETY   The standard catalog contains DESTRUCTIVE commands: Cold Reset (BMC
         reboot), Chassis Control (power off/cycle), Set User Password, Set
         LAN Config Params (can change the BMC IP and lock you out), Clear
         SEL, etc. By default this tool sends ONLY read-only commands (name
         does not begin with a write verb — see _is_destructive). Every
         skipped command is logged, not silently dropped. Pass --danger to
         send writes too — ONLY against a disposable target (QEMU vbmc /
         throwaway BMC).

USAGE    # read-only authenticated sweep of a known BMC
         python3 scripts/ipmi_sweep.py \
             --host idrac10 --user root --password '...' --cipher 3 \
             --out tests/golden/ipmi_responses_idrac10.json

         # pre-auth framing map (no creds) — the iDRAC10 diagnostic
         python3 scripts/ipmi_sweep.py --host idrac10 --sessionless \
             --out tests/golden/ipmi_sless_idrac10.json

         python3 scripts/ipmi_sweep.py --selfcheck   # offline self-test
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import zipmi  # noqa: F401  (registers base scapy layers)
from zipmi.core import Session, Transport
from zipmi.scapy_ipmi.cmd_names import IPMI_CMD_NAMES

# Completion codes we special-case in the summary (mirrors oem_sweep).
CC_OK = 0x00
CC_NO_RESPONSE = 0xFF   # our sentinel for timeout / empty reply
CC_INVALID_CMD = 0xC1   # command not registered on this BMC
CC_INSUFFICIENT_PRIV = 0xD4

# ponytail: destructive-command guard is a name-prefix heuristic, not a
# hand-maintained (netfn,cmd) denylist. Ceiling: a mis-named catalog entry
# could slip through. Upgrade path: explicit denylist if a future entry's
# name doesn't start with its verb. First word of the catalog name decides;
# these are the write/side-effect verbs in IPMI_CMD_NAMES.
WRITE_VERBS = {
    "Set", "Clear", "Reset", "Cold", "Warm", "Chassis",  # "Chassis Control/Reset"
    "Activate", "Deactivate", "Close", "Add", "Delete", "Cancel",
    "Arm", "Re-arm", "Suspend", "Manufacturing", "Alert", "Send",
    "Master", "Prepare", "Platform", "PET", "Error", "Bridge",
}


def _is_destructive(name: str) -> bool:
    """True if the command's catalog name begins with a write/side-effect verb.

    Read-only commands start with Get/List/Query/Read/Reserve and are safe to
    fire with an empty body. "Reserve …" allocs a reservation id but mutates
    nothing observable, so it stays on the safe side.
    """
    if not name or name.startswith("(reserved"):
        return True  # never probe reserved/unnamed slots by default
    return name.split()[0] in WRITE_VERBS


def cc_class(cc: int) -> str:
    if cc == CC_OK:
        return "ok"
    if cc == CC_NO_RESPONSE:
        return "no_response"
    if cc == CC_INVALID_CMD:
        return "unsupported"
    if cc == CC_INSUFFICIENT_PRIV:
        return "priv"
    return "cc_err"


def _auth_secret(args):
    """Password, or a RawKey when -K/--key was given (RAKP with raw Kuid bytes,
    same as the main zipmi CLI's -K)."""
    if not args.key:
        return args.password
    from zipmi.scapy_ipmi.crypto import RawKey
    return RawKey(bytes.fromhex(args.key.replace(":", "").replace(" ", "")))


def open_session(args) -> Session:
    s = Session(
        host=args.host,
        username=args.user,
        password=_auth_secret(args),
        lanplus=True,
        cipher_suite=args.cipher,
        timeout=args.timeout,
    )
    s.transport.port = args.port
    s.activate()
    return s


def _sless_send(t: Transport, netfn: int, cmd: int, req: bytes,
                seq: int, rmcp_plus: bool) -> tuple[int, bytes]:
    """One sessionless send; collapse timeout/short reply to (0xFF, b'')."""
    try:
        msg, _ = t.sessionless_request(netfn, cmd, req, rq_seq=seq,
                                       rmcp_plus=rmcp_plus)
    except OSError:
        return CC_NO_RESPONSE, b""
    if msg is None or not getattr(msg, "data", b""):
        return CC_NO_RESPONSE, b""
    body = bytes(msg.data)
    return body[0], body[1:]


def sweep_authenticated(args, catalog, req) -> tuple[dict, dict]:
    print(f"# ipmi_sweep (authenticated) -> {args.host}:{args.port} "
          f"cipher {args.cipher} user {args.user}", file=sys.stderr)
    s = open_session(args)
    print(f"# session up; granted_priv="
          f"{getattr(s, 'granted_priv', '?'):#x}", file=sys.stderr)

    res: dict[str, dict] = {}
    counts: dict[str, int] = {"skipped_write": 0}
    for (netfn, cmd), name in sorted(catalog.items()):
        key = f"0x{netfn:02x},0x{cmd:02x}"
        if not args.danger and _is_destructive(name):
            counts["skipped_write"] += 1
            print(f"  {key} {'SKIP':>8} write        {name}", file=sys.stderr)
            continue
        cc, data, err = None, b"", None
        for attempt in (1, 2):
            try:
                cc, data = s.send_raw(netfn, cmd, req)
                break
            except Exception as e:               # session dropped; re-open once
                err = f"{type(e).__name__}: {e}"
                if attempt == 1:
                    try:
                        time.sleep(1.0)
                        s = open_session(args)
                    except Exception as e2:
                        err = f"reopen failed: {type(e2).__name__}: {e2}"
                        break
        if cc is None:
            res[key] = {"name": name, "netfn": netfn, "cmd": cmd,
                        "request_hex": req.hex(), "error": err}
            klass = "error"
        else:
            res[key] = {"name": name, "netfn": netfn, "cmd": cmd,
                        "request_hex": req.hex(), "cc": cc,
                        "response_hex": data.hex()}
            klass = cc_class(cc)
        counts[klass] = counts.get(klass, 0) + 1
        tag = f"cc=0x{cc:02x}" if cc is not None else "ERR"
        print(f"  {key} {tag:>8} {klass:<11} {name}", file=sys.stderr)
    counts["total"] = len(catalog)
    return res, counts


def sweep_sessionless(args, catalog, req) -> tuple[dict, dict]:
    print(f"# ipmi_sweep (sessionless, framing={args.framing}) -> "
          f"{args.host}:{args.port}", file=sys.stderr)
    t = Transport(host=args.host, port=args.port, timeout=args.timeout)
    framings = (("ipmi15", False), ("rmcpplus", True)) if args.framing == "both" \
        else (("ipmi15", False),) if args.framing == "15" \
        else (("rmcpplus", True),)

    res: dict[str, dict] = {}
    counts: dict[str, int] = {"skipped_write": 0, "asymmetric": 0}
    seq = 0
    for (netfn, cmd), name in sorted(catalog.items()):
        key = f"0x{netfn:02x},0x{cmd:02x}"
        if not args.danger and _is_destructive(name):
            counts["skipped_write"] += 1
            print(f"  {key} {'SKIP':>8} write        {name}", file=sys.stderr)
            continue
        entry: dict = {"name": name, "netfn": netfn, "cmd": cmd,
                       "request_hex": req.hex(), "framings": {}}
        for label, rmcp_plus in framings:
            seq = (seq + 1) & 0x3F
            cc, data = _sless_send(t, netfn, cmd, req, seq, rmcp_plus)
            entry["framings"][label] = {"cc": cc, "response_hex": data.hex()}
            counts[cc_class(cc)] = counts.get(cc_class(cc), 0) + 1
        # Flag framing asymmetry: answers one wrapper, times out the other.
        if args.framing == "both":
            g15 = entry["framings"]["ipmi15"]["cc"]
            gpp = entry["framings"]["rmcpplus"]["cc"]
            asym = (g15 == CC_NO_RESPONSE) ^ (gpp == CC_NO_RESPONSE)
            entry["framing_asymmetric"] = asym
            if asym:
                counts["asymmetric"] += 1
        res[key] = entry
        tags = " ".join(f"{lab}=0x{entry['framings'][lab]['cc']:02x}"
                        for lab, _ in framings)
        mark = " <ASYM>" if entry.get("framing_asymmetric") else ""
        print(f"  {key} {tags:>24}  {name}{mark}", file=sys.stderr)
    counts["total"] = len(catalog)
    return res, counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=623)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="")
    ap.add_argument("-K", "--key", default="", metavar="HEX",
                    help="RAKP with raw Kuid key bytes (hex) instead of a "
                         "password — same as zipmi -K")
    ap.add_argument("--cipher", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--out", default="tests/golden/ipmi_responses.json")
    ap.add_argument("--sessionless", action="store_true",
                    help="no creds; sweep pre-auth over the raw transport")
    ap.add_argument("--framing", choices=("15", "plus", "both"), default="both",
                    help="sessionless only: which session wrapper(s) to try")
    ap.add_argument("--request-hex", default="",
                    help="hex request body sent with every cmd (default empty)")
    ap.add_argument("--danger", action="store_true",
                    help="ALSO send destructive (Set/Clear/Reset/…) commands — "
                         "disposable targets ONLY")
    ap.add_argument("--label", default="",
                    help="firmware label recorded in _meta (e.g. idrac10-6.10)")
    ap.add_argument("--selfcheck", action="store_true",
                    help="run offline self-test and exit")
    args = ap.parse_args()

    if args.selfcheck:
        return _selfcheck()

    req = bytes.fromhex(args.request_hex) if args.request_hex else b""
    catalog = IPMI_CMD_NAMES

    if args.danger:
        print("# --danger: destructive commands WILL be sent", file=sys.stderr)

    if args.sessionless:
        fixtures, counts = sweep_sessionless(args, catalog, req)
        mode = f"sessionless/{args.framing}"
    else:
        fixtures, counts = sweep_authenticated(args, catalog, req)
        mode = "authenticated"

    out = {
        "_meta": {
            "source": f"{args.host}:{args.port}",
            "label": args.label,
            "mode": mode,
            "cipher": args.cipher if not args.sessionless else None,
            "request_hex": req.hex(),
            "danger": args.danger,
            "note": "standard IPMI command sweep by scripts/ipmi_sweep.py; "
                    "read-only unless --danger given",
        },
        "summary": counts,
        "fixtures": fixtures,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")

    print("\n# ===== SUMMARY =====", file=sys.stderr)
    parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())
                      if k != "total")
    print(f"  {mode:<18} {counts['total']:>3} cmds: {parts}", file=sys.stderr)
    print(f"# wrote {args.out}", file=sys.stderr)
    return 0


def _selfcheck() -> int:
    # The destructive heuristic is the safety boundary — prove it classifies.
    safe = ["Get Device ID", "Get Chassis Status", "Get System GUID",
            "Reserve Device SDR Repository", "Get Channel Cipher Suites"]
    danger = ["Cold Reset", "Warm Reset", "Chassis Control", "Chassis Reset",
              "Set User Password", "Set LAN Config Params", "Clear SEL",
              "Set Channel Access", "(reserved)"]
    for n in safe:
        assert not _is_destructive(n), f"false-positive: {n!r} flagged destructive"
    for n in danger:
        assert _is_destructive(n), f"MISS: {n!r} not flagged destructive"
    # Every catalog entry classifies without error.
    for name in IPMI_CMD_NAMES.values():
        _is_destructive(name)
    n_safe = sum(1 for v in IPMI_CMD_NAMES.values() if not _is_destructive(v))
    print(f"selfcheck OK — {len(IPMI_CMD_NAMES)} catalog cmds, "
          f"{n_safe} read-only (swept by default), "
          f"{len(IPMI_CMD_NAMES) - n_safe} write (need --danger)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
