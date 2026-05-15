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
         /Volumes/yyy/phd/bmc/idrac9-firmware/idrac9-dispatch-tables.md.
"""
from __future__ import annotations

from ._registry import register
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


register("idrac9", DELL_IANA, IDRAC9_CMD_NAMES)


__all__ = [
    "DELL_IANA",
    "IDRAC9_CMD_NAMES",
    "IDRAC9_DISPATCH",
    "IDRAC9_PRIV",
]
