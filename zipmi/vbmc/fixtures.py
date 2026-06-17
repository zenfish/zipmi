"""
zipmi.vbmc.fixtures — load synthetic OEM response fixtures into a Persona.

WHAT     Parses the JSON produced by scripts/oem_sweep.py (a capture of what
         a real BMC answered for each vendor OEM command) into a
         `(netfn, cmd) -> (completion_code, response_bytes)` map, and applies
         it to a Persona's `oem_responses`.

WHY      Lets the vbmc replay faux-real vendor OEM answers with no live
         hardware: CI/tests, decoder validation, and — by hand-editing the
         JSON — coverage of proprietary vendors (Dell/SM) whose OEM commands
         shell out to vendor binaries we can't run.

FORMAT   {
           "fixtures": {
             "<vendor>": {
               "0xNN,0xMM": {"netfn": NN, "cmd": MM, "cc": C,
                             "response_hex": "..."},   # success/known-CC
               ...,
               "0xNN,0xMM": {"netfn": NN, "cmd": MM, "error": "..."},  # skipped
             }, ...
           }
         }
         Entries with no "cc" (transport errors) and entries whose cc is the
         sweep's no-response sentinel (0xFF) are skipped — the vbmc would have
         nothing faithful to send, so it falls through to 0xC1 Invalid Command.

RELATED  scripts/oem_sweep.py (producer), state.py (Persona.oem_responses),
         server.py (_dispatch fallback).
"""
from __future__ import annotations

import json

NO_RESPONSE_SENTINEL = 0xFF


def load_oem_fixture(
    path: str,
    vendors: list[str] | None = None,
) -> dict[tuple[int, int], tuple[int, bytes]]:
    """Read a sweep JSON file and return (netfn, cmd) -> (cc, data).

    `vendors` optionally restricts which vendor blocks are loaded. Later
    vendors win on (netfn, cmd) collisions (rare across OpenBMC flavors).
    """
    with open(path) as f:
        doc = json.load(f)

    blocks = doc.get("fixtures", doc)  # tolerate a bare {vendor: {...}} dict
    out: dict[tuple[int, int], tuple[int, bytes]] = {}
    for vendor, cmds in blocks.items():
        if vendors is not None and vendor not in vendors:
            continue
        if not isinstance(cmds, dict):
            continue
        for entry in cmds.values():
            if "cc" not in entry:
                continue                     # transport error — nothing to replay
            cc = int(entry["cc"])
            if cc == NO_RESPONSE_SENTINEL:
                continue                     # BMC dropped it; can't faithfully mock
            netfn = int(entry["netfn"])
            cmd = int(entry["cmd"])
            data = bytes.fromhex(entry.get("response_hex", ""))
            out[(netfn, cmd)] = (cc, data)
    return out


def apply_fixture(persona, path: str, vendors: list[str] | None = None) -> int:
    """Load `path` and merge it into `persona.oem_responses`. Returns count."""
    table = load_oem_fixture(path, vendors=vendors)
    persona.oem_responses.update(table)
    return len(table)
