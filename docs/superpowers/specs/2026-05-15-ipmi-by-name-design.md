# Design: `zipmi ipmi` — standard IPMI commands by name

**Status:** approved (design phase, 2026-05-15)
**Approach:** A — catalogue-source reuse of the existing OEM path

## Problem

`zipmi` can already invoke *vendor OEM* commands by human name
(`zipmi -H <bmc> dell GetChassisStatus`, `zipmi oem supermicro
UtilRestoreConfig`) and list a vendor's catalogue (`zipmi supermicro`).
There is no equivalent for the **standard** IPMI 2.0 command set: to
send `Get Channel Authentication Capabilities` you must know it is
NetFn `0x06` / cmd `0x38` and type `zipmi raw 0x06 0x38 …`.

`IPMI_CMD_NAMES` (`zipmi/scapy_ipmi/cmd_names.py`, `{(netfn,cmd) →
name}`, ~250 entries, IPMI 2.0 spec Table G-1) already holds every
name. The request is: expose the standard table through the same
name-resolution + listing UX the OEM catalogues use.

## Decisions (locked during brainstorming)

1. **Argument model: raw data bytes.** The name resolves only
   `(netfn, cmd)`; the user appends the request body themselves,
   exactly as `zipmi oem <vendor> <name> [data]` and `zipmi raw`
   already work. No per-command typed encoders. One path for all ~250
   commands.
2. **Name matching: identical to OEM.** Reuse `_find_cmd()` unchanged
   — 3-phase (literal substring → normalized exact → normalized
   substring). Unique match → send. Multiple → print candidate list,
   exit 1. No new matching logic, no exact-only divergence.
3. **Catalogue scope: `(netfn, cmd)` Table G-1 entries only.**
   `cmd_names.py` also defines RAKP / OpenSession / ASF pseudo-names;
   those are not `send_raw(netfn, cmd, data)`-addressable and would be
   dead listing rows, so they are excluded. (Determined by the
   `send_raw` interface, not a preference.)
4. **Placement: top-level `zipmi ipmi` verb**, sibling to the existing
   `zipmi supermicro` / `zipmi dell` shortcuts. **Not** added to
   `VENDORS`, so `zipmi oem` does not list `ipmi` as a vendor — it
   isn't one.
5. **Approach A naming.** The `vendor` parameter threaded through
   `oem_cmds.py` is treated as a *catalogue id*. Symbols are **not**
   mass-renamed (`_vendor_listing`, `cmd_oem_run` keep their names —
   renaming everything is unrelated churn); only the catalogue id is
   allowed to be a non-vendor (`"ipmi"`) and user-facing labels are
   corrected so the code/output does not call IPMI a "vendor".

## Architecture

One conceptual unit added: an **"ipmi" catalogue source** inside
`zipmi/cli/oem_cmds.py`. Everything else is existing, source-agnostic
machinery reused unchanged:

- `_find_cmd(listing, query)` — name resolution + ambiguity.
- `_normalize(s)` — prefix/separator-insensitive matching.
- `_normalize_listing(out, id)` — final listing pass.
- `cmd_oem_run(args, id)` — resolve → send → render (one guarded line
  changes; see below).
- `_print_vendor_listing(id)` — catalogue listing (one title line
  becomes catalogue-aware).
- `_add_vendor_parser(sub, key, blurb)` — argparse wiring (gains an
  optional help-noun argument).

Data flow:

```
zipmi -H h ipmi "Get Device ID" [bytes…]
  → cmd_oem_run(args, "ipmi")
  → _vendor_listing("ipmi")        # NEW branch: rows from IPMI_CMD_NAMES
  → _find_cmd(listing, "Get Device ID")   # existing OEM 3-phase
  → unique hit → _open_session(args)
  → s.send_raw(netfn, cmd, user_bytes)    # existing
  → print name + cc + reply               # existing
```

`zipmi ipmi` (no cmd) → `_print_vendor_listing("ipmi")` → full Table
G-1 catalogue. Ambiguous query → candidate list, exit 1 (existing
behaviour, no new code).

## Changes (all in `zipmi/cli/oem_cmds.py`)

1. **`_vendor_listing()`** — add an `if vendor == "ipmi":` branch that
   builds, from `IPMI_CMD_NAMES`:

   ```python
   out = {
       (netfn, cmd): {
           "name": name, "priv": None, "desc": "",
           "live": None, "missing": False,
           "prefix": None, "args": "",
           "src": "IPMI 2.0 spec, Table G-1",
       }
       for (netfn, cmd), name in IPMI_CMD_NAMES.items()
   }
   return _normalize_listing(out, "ipmi")
   ```

   Row shape matches what OEM rows provide; all downstream consumers
   read these keys via `.get(...)` with defaults (verified in
   `_print_vendor_listing`, `cmd_oem_run`, `_cmd_oem_help`).

   **Display-name note:** `_normalize_listing` camelizes every name
   (`"Get Device ID"` → `"GetDeviceID"`), same as for OEM catalogues —
   this is intentional and keeps `zipmi ipmi` listings visually
   consistent with `zipmi idrac6`/`supermicro`. Name *resolution* is
   unaffected: `_find_cmd` Phase-2 normalizes both sides, so
   `zipmi ipmi "Get Device ID"` still resolves (the spec's spaced,
   human form is what users type; the camelized form is only the
   listing display).

2. **`_vendor_stats()`** — add `if vendor == "ipmi": return (n, n)`
   where `n = len(IPMI_CMD_NAMES)` (total == named; no unnamed stubs).

3. **`_print_vendor_listing()`** — make the title catalogue-aware:
   `vendor == "ipmi"` → `"IPMI 2.0 standard commands (Table G-1) — N
   total"`; all other ids keep the existing `"<vendor> OEM commands …"`
   title. Single conditional on the title string only.

4. **`cmd_oem_run()`** — guard the pre-send vendor load:

   ```python
   if vendor != "ipmi":
       zipmi.load_vendor(vendor)
   ```

   Standard commands need no OEM dispatch table; `load_vendor("ipmi")`
   would raise. Everything else in `cmd_oem_run` (help intercept,
   resolve, ambiguity list, data-byte parse, `send_raw`, completion-
   code hints) is reused unchanged.

5. **`_add_vendor_parser()`** — add an optional `cmd_noun="OEM cmd"`
   parameter used only in the two `help=` strings, so the `ipmi`
   parser reads "IPMI cmd name (substring match; omit to list)"
   instead of "OEM cmd name". Existing call sites unchanged
   (default preserves current text).

6. **`add_oem_subparsers()`** — after the VENDORS loop, register the
   top-level `ipmi` verb (not inside the `oem` dispatcher, not in
   `VENDORS`):

   ```python
   _add_vendor_parser(top_sub, "ipmi",
                      "standard IPMI cmd by name (omit to list Table G-1)",
                      cmd_noun="IPMI cmd")
   ```

   `_add_vendor_parser` already adds `cmd_name` (nargs="?"), `data`
   (nargs="*"), and `set_defaults(func → cmd_oem_run(a, "ipmi"))`.

No new module. No change to `cmd_names.py` (already exports
`IPMI_CMD_NAMES`). No change to `core.py` / `send_raw`.

## Error handling

All inherited from `cmd_oem_run`, unchanged:

- No name match → message + "run `zipmi ipmi` to see the catalogue",
  exit 1.
- Ambiguous → candidate list (wire address + name), exit 1.
- Non-numeric data byte → error + hint, exit 2.
- Transport / IPMI error → via `_open_session` context manager.
- Non-zero completion code → existing per-CC hint block (0xC1
  "unimplemented", 0xD5 "disabled", etc.).

## Testing

**Unit (`tests/unit/`, no host):**

- `_vendor_listing("ipmi")` is non-empty, every row has the expected
  keys, count == `len(IPMI_CMD_NAMES)`.
- Resolution via `_find_cmd`: exact (`"Get Device ID"` → `(0x06,
  0x01)`), normalized (`"get-device-id"`, `"GetDeviceID"`), ambiguous
  (`"Get Chassis"` → ≥2 hits, listing path), no-match (→ `[]`).
- `"ipmi"` is **absent** from the `zipmi oem` vendor list
  (`VENDORS` unchanged; assert `"ipmi" not in VENDORS`).
- `cmd_oem_run` does **not** call `zipmi.load_vendor` when
  `vendor == "ipmi"` (monkeypatch `load_vendor` to raise; assert the
  resolve/list paths still work).
- `_print_vendor_listing("ipmi")` title contains "Table G-1" and not
  "OEM".

**Integration (`tests/integration/`, vbmc fixture):**

- Reuse the existing `vbmc_dell` fixture. `zipmi -H 127.0.0.1 -p
  <port> ipmi "Get Device ID"` → exit 0, output includes the device
  id; bare `zipmi ipmi` (no host) → lists the catalogue, exit 0.

## Doc-sync touchpoints

`scripts/check_doc_sync.py` (pre-commit) does substring / test-count
checks, not heading parsing — adding a verb does not by itself break
it. But the new verb must be documented or the change is incomplete:

- **README "zipmi verbs"** block (`<details>`-wrapped): add an `ipmi`
  row next to `raw` / `oem`.
- **README "OEM discovery and usage"**: one line noting standard
  commands have the same by-name UX (`zipmi ipmi "<name>" [bytes]`).
- Re-run `python scripts/check_doc_sync.py` before commit (expect rc
  0; 66 test count unchanged unless tests added — update the count
  string if integration/unit tests raise it).

## Scope / size

~40–60 LoC in `oem_cmds.py` (one listing branch, one stats line, one
title conditional, one guard line, one help-noun param, one parser
registration) + unit/integration tests + ~2 README lines. No new
module, no typed encoders, no divergence from the OEM code path.

## Out of scope (YAGNI)

- Typed per-command argument encoders / named flags.
- Privilege / description columns for the IPMI listing (Table G-1 has
  privilege but `IPMI_CMD_NAMES` does not store it; minimal listing is
  consistent with the OEM-path reuse).
- RAKP / ASF / session pseudo-names in the catalogue.
- Adding `ipmi` to `zipmi oem` as a pseudo-vendor.
