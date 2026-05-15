"""
zipmi.cli.groups_cmds — `zipmi groups [body [cmd [data ...]]]` + shortcuts.

WHAT     Mirror of cli/oem_cmds.py but for IPMI Group Extension cmds
         (NetFn 0x2C/0x2D). Three verbs:
           * `zipmi groups`              — list group bodies (DCMI, ...)
           * `zipmi groups <body>`       — list that body's cmds
           * `zipmi groups <body> <name> [data]` — run cmd by name
         Each body gets a top-level shortcut: `zipmi dcmi ...`.

WHY      Group cmds share the OEM-by-name UX but the wire framing is
         different: NetFn 0x2C with a group-code byte (0xDC for DCMI)
         prepended to every payload. Keeping the dispatcher separate
         from oem_cmds keeps the wire-framing logic clean and lets
         each namespace evolve independently as PICMG / HPM / VITA
         get added.

SUCCESS  `zipmi -H <bmc> dcmi GetCapabilities` sends NetFn 0x2C cmd
         0x01 with first data byte 0xDC; response strips the echoed
         0xDC and prints the body.

RELATED  zipmi.scapy_ipmi.groups.{dcmi}, groups/_registry.py,
         cli.oem_cmds (sibling dispatcher).
"""
from __future__ import annotations

import argparse
import re
import sys

from ..scapy_ipmi.commands import COMP_CODE


# Body manifest. Add a key here to surface a new group body on the CLI.
GROUPS: dict[str, dict] = {
    "dcmi": {
        "code": 0xDC,
        "blurb": "DCMI 1.5 (Data Center Manageability Interface) — "
                 "power / thermal / asset",
    },
    # future:
    # "picmg": {"code": 0x00, "blurb": "PICMG 3.x / AMC.0 — ATCA shelves"},
    # "hpm":   {"code": 0x04, "blurb": "PICMG HPM.1 / HPM.2 — firmware upgrade"},
    # "vita":  {"code": 0x03, "blurb": "VITA 46.11 — VPX / OpenVPX"},
}


def _body_listing(body: str) -> list[dict]:
    """Return ordered rows of {verb, name, key, priv, desc, mo, prefix}.

    Verbs are the ipmitool-style command names users actually type
    (`power reading`, `discover`). Listing order is the source order
    in DCMI_VERBS so help mirrors ipmitool's verb layout.
    """
    if body == "dcmi":
        from ..scapy_ipmi.groups.dcmi import (
            DCMI_CMD_NAMES, DCMI_META, DCMI_VERBS,
        )
        rows = []
        for v in DCMI_VERBS:
            key = v["key"]
            spec = DCMI_CMD_NAMES.get(key, "")
            # Drop redundant body prefix from displayed spec name.
            disp = spec
            for tag in ("DCMI Get DCMI ", "DCMI Get ", "DCMI Set DCMI ",
                        "DCMI Set ", "DCMI Activate/Deactivate ",
                        "DCMI Activate/", "DCMI "):
                if disp.startswith(tag):
                    disp = tag.split(" ", 1)[1] + disp[len(tag):] \
                        if " " in tag else disp[len(tag):]
                    disp = disp.lstrip()
                    break
            meta = DCMI_META.get(key, {})
            rows.append({
                "verb":   v["verb"],
                "name":   disp,
                "key":    key,
                "priv":   meta.get("priv"),
                "desc":   meta.get("desc"),
                "mo":     meta.get("mo"),
                "prefix": v.get("prefix"),
            })
        return rows
    raise KeyError(f"unknown group body: {body}")


# Name normalisation — strip body filler (DCMI / PICMG / HPM / VITA /
# Cmd) wherever it appears, plus all separators, lowercase. Used for
# verb matching AND fallback substring search on the spec name.
_FILLER_RE = re.compile(r"\b(?:dcmi|picmg|hpm|vita|cmd)\b", re.IGNORECASE)


def _normalize(s: str) -> str:
    s = _FILLER_RE.sub("", s)
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _find_row(rows: list[dict], cmd_name: str,
              data_args: list[str]) -> tuple[dict | None, list[str]]:
    """Resolve user input to a row.

    Strategy:
      1. Multi-token verb match (longest first). `power activate` →
         row for cmd 0x05 prefix [0x01, 0x00, 0x00], no leftover args.
      2. Single-token verb match.
      3. Fallback: substring match on the displayed spec name.

    Returns (row | None, leftover_data_args).
    """
    tokens = [cmd_name] + list(data_args)
    # 1+2: verb match (try 3-token down to 1-token).
    for n in range(min(3, len(tokens)), 0, -1):
        candidate = _normalize(" ".join(tokens[:n]))
        if not candidate:
            continue
        for row in rows:
            if _normalize(row["verb"]) == candidate:
                return row, tokens[n:]
    # 3: fallback substring on spec name.
    qn = _normalize(cmd_name)
    if qn:
        hits = [r for r in rows if qn in _normalize(r["name"])]
        if len(hits) == 1:
            return hits[0], list(data_args)
        if len(hits) > 1:
            return {"_ambiguous": hits}, []
    return None, list(data_args)


def _print_body_listing(body: str) -> None:
    rows = _body_listing(body)
    if not rows:
        print(f"# {body}: no cmds registered", file=sys.stderr)
        return
    code = GROUPS[body]["code"]
    title = (f"{body} verbs (NetFn 0x2C / group 0x{code:02x}) "
             f"— {len(rows)} verbs")
    print(f"# {title}")
    print("# " + "-" * len(title))
    cells: list[tuple[str, str, str, str]] = []
    for r in rows:
        meta_bits: list[str] = []
        if r.get("mo"):
            meta_bits.append(f"[{r['mo']}]")
        if r.get("priv"):
            meta_bits.append(f"[{r['priv']}]")
        cells.append((r["verb"], r["name"], "  ".join(meta_bits),
                      r.get("desc") or ""))
    verb_w = max(max(len(c[0]) for c in cells), len("Verb"))
    name_w = max(max(len(c[1]) for c in cells), len("Spec name"))
    meta_w = max(len(c[2]) for c in cells)
    has_meta = any(c[2] for c in cells)
    has_desc = any(c[3] for c in cells)
    hdr = f"  {'Verb':<{verb_w}s}    {'Spec name':<{name_w}s}"
    sep = f"  {'-'*verb_w}    {'-'*name_w}"
    if has_meta:
        hdr += f"  {'M/O Priv':<{meta_w}s}"
        sep += f"  {'-'*meta_w}"
    if has_desc:
        hdr += "  Description"
        sep += "  -----------"
    print(hdr)
    print(sep)
    for verb, name, meta, desc in cells:
        line = f"  {verb:<{verb_w}s}    {name:<{name_w}s}"
        if has_meta:
            line += f"  {meta:<{meta_w}s}"
        if has_desc and desc:
            line += f"  => {desc}"
        print(line.rstrip())
    print()
    print(f"# Run a command:  zipmi -H <host> -U <u> -P <p> "
          f"{body} <name> [data ...]")


def _print_groups_catalog() -> None:
    print("# zipmi Group Extension dispatcher (NetFn 0x2C)")
    print("# Available group bodies (`zipmi groups <body>` to list cmds):")
    for body, info in GROUPS.items():
        listing = _body_listing(body) if body == "dcmi" else {}
        n = len(listing)
        print(f"  {body:<8s}  group 0x{info['code']:02x}  "
              f"{n:>3d} cmds  {info['blurb']}")
    print()
    print("# Group cmds ride NetFn 0x2C with the group-code byte (e.g.")
    print("# 0xDC for DCMI) as the first data byte. zipmi prepends it")
    print("# automatically — supply only the cmd-specific bytes after.")
    print()
    print("# Run by name:  zipmi <body> <cmd-name> [data-bytes ...]")
    print("# Or:           zipmi groups <body> <cmd-name> [data-bytes ...]")


# --- entry points -------------------------------------------------------


def cmd_groups_list(args: argparse.Namespace) -> int:
    """`zipmi groups` — list bodies, or dispatch if a body is given."""
    body = getattr(args, "body", None)
    if body:
        return cmd_group_run(args, body)
    _print_groups_catalog()
    return 0


def cmd_group_run(args: argparse.Namespace, body: str) -> int:
    """`zipmi <body> [verb [data ...]]`."""
    cmd_name = getattr(args, "cmd_name", None)
    if not cmd_name:
        _print_body_listing(body)
        return 0

    try:
        rows = _body_listing(body)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    data_args = list(getattr(args, "data", None) or [])
    row, leftover = _find_row(rows, cmd_name, data_args)
    if row is None:
        print(f"no {body} verb matches {cmd_name!r}", file=sys.stderr)
        print(f"# Run `zipmi {body}` to see the verb list.",
              file=sys.stderr)
        return 1
    if "_ambiguous" in row:
        print(f"# multiple {body} verbs match {cmd_name!r}:",
              file=sys.stderr)
        for r in row["_ambiguous"]:
            print(f"  {r['verb']:<22s} {r['name']}", file=sys.stderr)
        return 1

    group_code, cmd = row["key"]
    prefix = row.get("prefix") or b""
    try:
        user_bytes = bytes(int(b, 0) & 0xFF for b in leftover)
    except ValueError:
        bad = next((b for b in leftover
                    if not _is_int_literal(b)), None)
        print(f"error: data byte {bad!r} is not numeric "
              f"(use hex 0xNN or decimal)", file=sys.stderr)
        return 2
    # Wire framing: NetFn 0x2C, cmd byte, data = [group_code] + verb-prefix + user.
    payload = bytes([group_code]) + prefix + user_bytes

    from .zipmi import _open_session  # noqa: WPS433
    from .oem_cmds import _suggest_for_cc

    with _open_session(args) as s:
        cc, resp = s.send_raw(0x2C, cmd, payload)

    print(f"# {body} {row['verb']}  (NetFn 0x2C cmd 0x{cmd:02x}, "
          f"group 0x{group_code:02x})", file=sys.stderr)
    if cc != 0:
        cc_name = COMP_CODE.get(cc, f"0x{cc:02x}")
        print(f"completion code: {cc_name}", file=sys.stderr)
        # Synthesise a fake info dict so the shared hinter can show desc.
        _suggest_for_cc(cc, 0x2C, cmd,
                        {"desc": row.get("desc")}, body)
        return 1
    if resp:
        if resp[:1] == bytes([group_code]):
            resp = resp[1:]
        print(" ".join(f"{b:02x}" for b in resp))
    return 0


def _is_int_literal(s: str) -> bool:
    try:
        int(s, 0)
        return True
    except (ValueError, TypeError):
        return False


# --- argparse wiring ----------------------------------------------------


def _add_body_parser(parent_sub, body_key: str, blurb: str):
    sp = parent_sub.add_parser(body_key, help=blurb)
    sp.add_argument("cmd_name", nargs="?",
                    help="cmd name (substring match; omit to list)")
    sp.add_argument("data", nargs="*",
                    help="optional cmd-specific data bytes (hex 0x.. or decimal)")
    sp.set_defaults(func=lambda a, b=body_key: cmd_group_run(a, b))
    return sp


def add_groups_subparsers(top_sub) -> None:
    """Wire `zipmi groups` and per-body shortcuts (zipmi dcmi, ...)."""
    # Top-level shortcuts.
    for bkey, binfo in GROUPS.items():
        _add_body_parser(top_sub, bkey, binfo["blurb"])
    # Dispatcher.
    g = top_sub.add_parser("groups",
                           help="IPMI Group Extension dispatcher (NetFn 0x2C)")
    g.set_defaults(func=cmd_groups_list)
    g_sub = g.add_subparsers(dest="body")
    for bkey, binfo in GROUPS.items():
        _add_body_parser(g_sub, bkey, binfo["blurb"])


__all__ = [
    "GROUPS",
    "add_groups_subparsers",
    "cmd_groups_list",
    "cmd_group_run",
]
