"""
zipmi.scapy_ipmi.oem.idrac9 — Dell iDRAC9 OEM command registration.

WHAT     Loads the iDRAC9 dispatch tables (recovered from rootfs ELF .so
         libs) and the handler-name catalog (from the upstream RE doc),
         cross-references them, and registers (NetFn, cmd) → name into
         the OEM registry. Activates via `zipmi.load_vendor("idrac9")`.
WHY      iDRAC9 ships ~60 IPMI .so libs with hundreds of handlers. The
         binary dispatch tables in liboemcmds / libdcmi / libosa carry
         (cmd, netfn, priv) bytes for the OEM/DCMI/OSA range; the
         handler-symbol catalog provides human cmd names. Together they
         turn iDRAC9 from a name-only catalog into a fuzz-ready surface.
SUCCESS  After load_vendor("idrac9"), OEM_CMD_NAMES gains ≥ 270 entries.
TARGET   iDRAC9 firmware (firmimgFIT.d9) v7.20.30.50, Dell IANA 674.
RELATED  zipmi/parsers/idrac9_dispatch_md.py (codegen),
         iDRAC9 firmware dispatch tables (internal RE).
"""
from __future__ import annotations

from ._registry import OEM_CMD_NAMES, register
from .idrac9_commands_generated import IDRAC9_COMMANDS, IDrac9Command
from .idrac9_dispatch_generated import IDRAC9_DISPATCH, IDrac9DispatchEntry
from .idrac9_generated import IDRAC9_HANDLERS, IDrac9Handler

DELL_IANA = 674  # iDRAC9 reuses Dell's IANA Enterprise Number


def _humanize_handler(sym: str) -> str:
    """Strip 'Cmd' / 'OEM' prefixes and split CamelCase into spaced words."""
    name = sym
    for prefix in ("DellCmdOEM", "CmdOEM", "DellCmd", "Cmd", "OEM"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    out = []
    for i, c in enumerate(name):
        if c.isupper() and i and not name[i - 1].isupper():
            out.append(" ")
        out.append(c)
    return "".join(out).strip()


# Build handler-symbol → human cmd_name from the upstream RE doc.
_HANDLER_TO_NAME: dict[str, str] = {h.handler: h.cmd_name for h in IDRAC9_HANDLERS}


def _resolve_name(e: IDrac9DispatchEntry) -> str | None:
    """Return a name when we have one; None for runtime-bound stubs.

    Skipping unknowns keeps iDRAC9 from clobbering more-specific names
    that other vendors (e.g. Dell iDRAC6) registered for the same
    (NetFn, cmd) pair. The priv level is still preserved via IDRAC9_PRIV.
    """
    sym = e.handler_symbol
    if sym in _HANDLER_TO_NAME:
        return f"iDRAC9 {_HANDLER_TO_NAME[sym]}"
    if sym and sym != "(runtime-bound)":
        return f"iDRAC9 {_humanize_handler(sym)}"
    return None


IDRAC9_CMD_NAMES: dict[tuple[int, int], str] = {
    (e.netfn, e.cmd): name
    for e in IDRAC9_DISPATCH.values()
    if (name := _resolve_name(e)) is not None
}


# (NetFn, cmd) sets that the central tables register at non-trivial
# privilege. Useful for fuzz triage and "what privilege does cmd X want?"
IDRAC9_PRIV: dict[tuple[int, int], int] = {
    (e.netfn, e.cmd): e.priv for e in IDRAC9_DISPATCH.values()
}


# --- Rich per-command catalog (idrac9-commands.json, 276 entries) -----------
# The dispatch tables above name the wire surface; the catalog adds the
# human doc (purpose/request/response/security). 43 entries are PLT-shim
# handlers with request/response="undetermined" (payload logic lives in
# delegate libs) — they still carry a pinned (NetFn, cmd, subcmd) so they
# index normally. iDRAC9 has several (NetFn, cmd) that differ only by
# sub-command byte, so the by-key index maps to a list.
IDRAC9_COMMANDS_BY_KEY: dict[tuple[int, int], list[IDrac9Command]] = {}
for _c in IDRAC9_COMMANDS:
    if _c.netfn is None or _c.cmd is None:
        continue
    IDRAC9_COMMANDS_BY_KEY.setdefault((_c.netfn, _c.cmd), []).append(_c)

# (NetFn, cmd) → catalog name. First-writer-wins on sub-command collisions.
IDRAC9_COMMAND_NAMES: dict[tuple[int, int], str] = {}
for _c in IDRAC9_COMMANDS:
    if _c.netfn is None or _c.cmd is None:
        continue
    IDRAC9_COMMAND_NAMES.setdefault((_c.netfn, _c.cmd), f"iDRAC9 {_c.name}")


# Register the dispatch-derived names first, then layer the rich catalog on
# top for iDRAC9's own slots. But never clobber a (NetFn, cmd) another
# vendor already claimed with a specific name — Dell/iDRAC6/iDRAC10 all reuse
# IANA 674 and genuinely share wire slots. First vendor to name a slot keeps
# it, matching the documented non-clobber rule.
register("idrac9", DELL_IANA, IDRAC9_CMD_NAMES)
_claimed = set(OEM_CMD_NAMES)
register("idrac9", DELL_IANA,
         {k: v for k, v in IDRAC9_COMMAND_NAMES.items() if k not in _claimed})


def lookup(netfn: int, cmd: int,
           subcmd: int | None = None) -> list[IDrac9Command]:
    """Full-doc lookup for a wire (NetFn, cmd[, subcmd]).

    Returns every catalog command at that (NetFn, cmd). When `subcmd` is
    given, narrows to commands whose sub-command matches (a command with no
    sub-command byte, subcmd=None, always matches so the base handler is
    still returned). Empty list = not in the catalog.
    """
    hits = IDRAC9_COMMANDS_BY_KEY.get((netfn, cmd), [])
    if subcmd is None:
        return list(hits)
    return [c for c in hits if c.subcmd == subcmd or c.subcmd is None]


__all__ = [
    "DELL_IANA",
    "IDRAC9_CMD_NAMES",
    "IDRAC9_COMMANDS",
    "IDRAC9_COMMANDS_BY_KEY",
    "IDRAC9_COMMAND_NAMES",
    "IDRAC9_DISPATCH",
    "IDRAC9_PRIV",
    "IDrac9Command",
    "lookup",
]
