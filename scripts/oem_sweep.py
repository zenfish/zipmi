#!/usr/bin/env python3
"""oem_sweep.py — brute-force every OpenBMC OEM command via zipmi's own
command catalogs against a live BMC (or vbmc), recording (cc, response) for
each as faux-real fixtures.

WHAT     For each OpenBMC vendor flavor (intel/facebook/google/ampere) it
         walks the vendor's <VENDOR>_CMD_NAMES table, sends every
         (NetFn,Cmd) with an empty request body via Session.send_raw, and
         records the raw completion code + response bytes.

WHY      Two purposes:
           1. Validation baseline — re-run after a zipmi change and diff the
              JSON to catch regressions in what we send / how we decode.
           2. Synthetic-response seed — the captured (cc, data) become
              faux-real fixtures the vbmc can replay so tests/CI don't need
              a live BMC (see zipmi/vbmc + personas/synthetic.py).

USAGE    python3 scripts/oem_sweep.py \
              --host 192.168.0.22 --port 6230 --cipher 17 \
              --user root --password 0penBmc \
              --out tests/golden/oem_responses_openbmc.json

NOTE     Empty request body is the consistent baseline: no-arg commands
         return real data; data-requiring commands return 0xC7 (data len) or
         0xCC — still a faithful capture of "what the handler answers." A
         later pass can supply per-command request payloads for richer data.
         Brute-forcing hits side-effecty commands; only safe against a
         disposable target (QEMU vbmc / throwaway BMC).
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
import time

import zipmi  # noqa: F401  (registers base layers)
from zipmi.core import Session

# vendor key -> (module, CMD_NAMES dict attr). These are the OpenBMC OEM
# flavors whose providers ship in the romulus oem-test image.
VENDORS = {
    "intel": ("zipmi.scapy_ipmi.oem.intel", "INTEL_CMD_NAMES"),
    "facebook": ("zipmi.scapy_ipmi.oem.facebook", "FACEBOOK_CMD_NAMES"),
    "google": ("zipmi.scapy_ipmi.oem.google", "GOOGLE_CMD_NAMES"),
    "ampere": ("zipmi.scapy_ipmi.oem.ampere", "AMPERE_CMD_NAMES"),
}

# IPMI completion codes we special-case in the summary.
CC_OK = 0x00
CC_NO_RESPONSE = 0xFF  # send_raw's sentinel for timeout / empty reply
CC_INVALID_CMD = 0xC1  # command not registered on this BMC
CC_INSUFFICIENT_PRIV = 0xD4


def load_catalog(modname: str, attr: str) -> dict:
    mod = importlib.import_module(modname)
    return getattr(mod, attr)


def open_session(args) -> Session:
    s = Session(
        host=args.host,
        username=args.user,
        password=args.password,
        lanplus=True,
        cipher_suite=args.cipher,
        timeout=args.timeout,
    )
    s.transport.port = args.port
    s.activate()
    return s


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="192.168.0.22")
    ap.add_argument("--port", type=int, default=6230)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="0penBmc")
    ap.add_argument("--cipher", type=int, default=17)
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--out", default="tests/golden/oem_responses_openbmc.json")
    ap.add_argument("--vendors", nargs="*", default=list(VENDORS))
    ap.add_argument("--request-hex", default="",
                    help="hex request body sent with every cmd (default empty)")
    args = ap.parse_args()

    req = bytes.fromhex(args.request_hex) if args.request_hex else b""

    print(f"# oem_sweep -> {args.host}:{args.port} cipher {args.cipher} "
          f"user {args.user}", file=sys.stderr)
    s = open_session(args)
    print(f"# session up; granted_priv={getattr(s, 'granted_priv', '?'):#x}",
          file=sys.stderr)

    fixtures: dict[str, dict] = {}
    summary: dict[str, dict] = {}

    for vendor in args.vendors:
        modname, attr = VENDORS[vendor]
        catalog = load_catalog(modname, attr)
        vres: dict[str, dict] = {}
        counts: dict[str, int] = {}
        print(f"\n## {vendor} — {len(catalog)} cmds", file=sys.stderr)
        for (netfn, cmd), name in sorted(catalog.items()):
            key = f"0x{netfn:02x},0x{cmd:02x}"
            cc, data, err = None, b"", None
            for attempt in (1, 2):
                try:
                    cc, data = s.send_raw(netfn, cmd, req)
                    break
                except Exception as e:  # session may have dropped; re-open once
                    err = f"{type(e).__name__}: {e}"
                    if attempt == 1:
                        try:
                            time.sleep(1.0)
                            s = open_session(args)
                        except Exception as e2:
                            err = f"reopen failed: {type(e2).__name__}: {e2}"
                            break
            if cc is None:
                entry = {"name": name, "netfn": netfn, "cmd": cmd,
                         "request_hex": req.hex(), "error": err}
                klass = "error"
            else:
                entry = {"name": name, "netfn": netfn, "cmd": cmd,
                         "request_hex": req.hex(), "cc": cc,
                         "response_hex": data.hex()}
                klass = cc_class(cc)
            vres[key] = entry
            counts[klass] = counts.get(klass, 0) + 1
            tag = f"cc=0x{cc:02x}" if cc is not None else "ERR"
            print(f"  {key} {tag:>8} {klass:<11} {name}", file=sys.stderr)
        fixtures[vendor] = vres
        counts["total"] = len(catalog)
        summary[vendor] = counts

    out = {
        "_meta": {
            "source": f"{args.host}:{args.port}",
            "cipher": args.cipher,
            "request_hex": req.hex(),
            "note": "faux-real OEM responses captured by scripts/oem_sweep.py; "
                    "empty request body unless --request-hex given",
        },
        "summary": summary,
        "fixtures": fixtures,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")

    print("\n# ===== SUMMARY =====", file=sys.stderr)
    for vendor, c in summary.items():
        parts = ", ".join(f"{k}={v}" for k, v in sorted(c.items()) if k != "total")
        print(f"  {vendor:<10} {c['total']:>3} cmds: {parts}", file=sys.stderr)
    print(f"\n# wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
