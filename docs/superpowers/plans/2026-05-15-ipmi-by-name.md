# `zipmi ipmi` Standard-Command-By-Name Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a top-level `zipmi ipmi [name] [bytes…]` verb that lists/sends standard IPMI 2.0 (Table G-1) commands by human name, reusing the existing OEM catalogue path.

**Architecture:** `IPMI_CMD_NAMES` (`{(netfn,cmd)→name}`) becomes an "ipmi" *catalogue source* inside `zipmi/cli/oem_cmds.py`. All resolution/listing/send machinery (`_find_cmd`, `_normalize_listing`, `cmd_oem_run`, `_print_vendor_listing`, `_add_vendor_parser`) is reused unchanged except: one `_vendor_listing` branch, one `_vendor_stats` branch, one catalogue-aware title, one `load_vendor` guard, one optional help-noun param, one parser registration. No new module, no typed encoders.

**Tech Stack:** Python 3.11+, argparse, pytest. Spec: `docs/superpowers/specs/2026-05-15-ipmi-by-name-design.md`.

---

## Files

- Modify: `zipmi/cli/oem_cmds.py` — add `"ipmi"` catalogue source + parser registration (Tasks 1, 3, 4, 5)
- Create: `tests/unit/test_ipmi_catalogue.py` — unit coverage (Tasks 1, 2, 3, 4, 5)
- Modify: `tests/integration/test_vbmc_loopback.py` — one end-to-end test reusing the `vbmc_dell` fixture (Task 6)
- Modify: `README.md` — `zipmi verbs` row + OEM-discovery line (Task 7)

Pattern notes (follow existing code):
- `_vendor_listing()` uses **function-local imports per source** (e.g. `from ..scapy_ipmi.oem.dell_generated import DELL_DISPATCH`). The `ipmi` branch must do the same: `from ..scapy_ipmi.cmd_names import IPMI_CMD_NAMES` inside the branch.
- A listing row is a dict with keys `name, priv, desc, live, missing, prefix, args, src`. All consumers read them via `.get()` with defaults.
- `_vendor_listing()` ends with `raise KeyError(f"unknown vendor: {vendor}")`. New branches go **before** that line.

---

### Task 1: `ipmi` catalogue source (`_vendor_listing` + `_vendor_stats`)

**Files:**
- Modify: `zipmi/cli/oem_cmds.py` (`_vendor_listing`, ends ~line 530 with `raise KeyError`; `_vendor_stats`, ends ~line 82 with `return 0, 0`)
- Test: `tests/unit/test_ipmi_catalogue.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_ipmi_catalogue.py`:

```python
"""Unit coverage for the `ipmi` standard-command catalogue source."""
from zipmi.cli.oem_cmds import _vendor_listing, _vendor_stats
from zipmi.scapy_ipmi.cmd_names import IPMI_CMD_NAMES


def test_ipmi_listing_shape_and_size():
    listing = _vendor_listing("ipmi")
    assert listing, "ipmi listing must be non-empty"
    assert len(listing) == len(IPMI_CMD_NAMES)
    # Get Device ID is App NetFn 0x06 / cmd 0x01.
    assert (0x06, 0x01) in listing
    row = listing[(0x06, 0x01)]
    for k in ("name", "priv", "desc", "live", "missing",
              "prefix", "args", "src"):
        assert k in row, f"row missing key {k!r}"
    # _normalize_listing camelizes display names (same as OEM
    # catalogues): "Get Device ID" -> "GetDeviceID". Resolution still
    # accepts the spaced form (covered in Task 2).
    assert row["name"] == "GetDeviceID"
    assert row["prefix"] is None
    assert "Table G-1" in row["src"]


def test_ipmi_stats_total_equals_named():
    total, named = _vendor_stats("ipmi")
    assert total == named == len(IPMI_CMD_NAMES)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q`
Expected: FAIL — `KeyError: 'unknown vendor: ipmi'` (and `_vendor_stats` returns `(0, 0)`).

- [ ] **Step 3: Add the `ipmi` branch to `_vendor_listing`**

In `zipmi/cli/oem_cmds.py`, immediately **before** the final
`raise KeyError(f"unknown vendor: {vendor}")` in `_vendor_listing`,
insert:

```python
    if vendor == "ipmi":
        from ..scapy_ipmi.cmd_names import IPMI_CMD_NAMES
        out: dict[tuple[int, int], dict] = {
            (netfn, cmd): {
                "name": name,
                "priv": None,
                "desc": "",
                "live": None,
                "missing": False,
                "prefix": None,
                "args": "",
                "src": "IPMI 2.0 spec, Table G-1",
            }
            for (netfn, cmd), name in IPMI_CMD_NAMES.items()
        }
        return _normalize_listing(out, "ipmi")
```

- [ ] **Step 4: Add the `ipmi` branch to `_vendor_stats`**

In `_vendor_stats`, immediately **before** the final `return 0, 0`,
insert:

```python
    if vendor == "ipmi":
        from ..scapy_ipmi.cmd_names import IPMI_CMD_NAMES
        n = len(IPMI_CMD_NAMES)
        return n, n
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add zipmi/cli/oem_cmds.py tests/unit/test_ipmi_catalogue.py
git commit -m "feat(cli): ipmi catalogue source in _vendor_listing/_vendor_stats"
```

---

### Task 2: Name resolution behaves like OEM

No production code — proves `_find_cmd` (existing, unchanged) resolves
against the `ipmi` listing exactly per spec decision 2.

**Files:**
- Test: `tests/unit/test_ipmi_catalogue.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_ipmi_catalogue.py`:

```python
from zipmi.cli.oem_cmds import _find_cmd


def _hits(query):
    return _find_cmd(_vendor_listing("ipmi"), query)


def test_exact_name_unique():
    hits = _hits("Get Device ID")
    assert len(hits) == 1
    assert hits[0][0] == (0x06, 0x01)


def test_normalized_forms_unique():
    for q in ("get-device-id", "GetDeviceID", "get_device_id"):
        hits = _hits(q)
        assert len(hits) == 1, q
        assert hits[0][0] == (0x06, 0x01)


def test_ambiguous_substring_lists_many():
    hits = _hits("Get Chassis")
    assert len(hits) >= 2  # Capabilities + Status (+ more)


def test_no_match_returns_empty():
    assert _hits("DefinitelyNotAnIpmiCommandXYZ") == []
```

- [ ] **Step 2: Run test to verify it passes immediately**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q`
Expected: PASS (Task 1 already supplies the listing; `_find_cmd` is
existing behaviour). This task is a behaviour lock, not new code — if
any assertion fails it is a real regression, stop and investigate.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_ipmi_catalogue.py
git commit -m "test(cli): lock OEM-identical name resolution for ipmi catalogue"
```

---

### Task 3: Catalogue-aware listing title

`_print_vendor_listing` currently hardcodes `"{vendor} OEM commands …"`.
For `ipmi` it must not say "OEM".

**Files:**
- Modify: `zipmi/cli/oem_cmds.py` (`_print_vendor_listing`, title block — the `if total != named:` / `else:` that sets `title`, followed by `print(f"# {title} …")`)
- Test: `tests/unit/test_ipmi_catalogue.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_ipmi_catalogue.py`:

```python
from zipmi.cli.oem_cmds import _print_vendor_listing


def test_ipmi_listing_title_not_oem(capsys):
    _print_vendor_listing("ipmi")
    out = capsys.readouterr().out
    first = out.splitlines()[0]
    assert "Table G-1" in first
    assert "OEM" not in first
    assert "GetDeviceID" in out  # a real row rendered (camelized)


def test_vendor_listing_title_unchanged(capsys):
    _print_vendor_listing("supermicro")
    first = capsys.readouterr().out.splitlines()[0]
    assert "OEM commands" in first
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q -k title`
Expected: FAIL — `test_ipmi_listing_title_not_oem` (title reads
`"ipmi OEM commands — N total"`, contains "OEM").

- [ ] **Step 3: Make the title catalogue-aware**

In `_print_vendor_listing`, replace the existing title block:

```python
    total, named = _vendor_stats(vendor)
    if total != named:
        title = (f"{vendor} OEM commands — {named} named "
                 f"of {total} known dispatch slots")
    else:
        title = f"{vendor} OEM commands — {named} total"
    print(f"# {title}  (`zipmi {vendor} <name> help` for per-cmd detail)")
```

with:

```python
    total, named = _vendor_stats(vendor)
    if vendor == "ipmi":
        title = f"IPMI 2.0 standard commands (Table G-1) — {named} total"
    elif total != named:
        title = (f"{vendor} OEM commands — {named} named "
                 f"of {total} known dispatch slots")
    else:
        title = f"{vendor} OEM commands — {named} total"
    print(f"# {title}  (`zipmi {vendor} <name> help` for per-cmd detail)")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q -k title`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/oem_cmds.py tests/unit/test_ipmi_catalogue.py
git commit -m "feat(cli): catalogue-aware title for `zipmi ipmi` listing"
```

---

### Task 4: `load_vendor` guard in `cmd_oem_run`

`cmd_oem_run` calls `zipmi.load_vendor(vendor)` before sending.
`load_vendor("ipmi")` is invalid (no OEM table); standard cmds need
none.

**Files:**
- Modify: `zipmi/cli/oem_cmds.py` (`cmd_oem_run`, line `zipmi.load_vendor(vendor)` ~786)
- Test: `tests/unit/test_ipmi_catalogue.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_ipmi_catalogue.py`:

```python
import zipmi


def test_cmd_oem_run_skips_load_vendor_for_ipmi(monkeypatch, capsys):
    """ipmi must NOT trigger zipmi.load_vendor (would raise)."""
    def boom(v):
        raise AssertionError(f"load_vendor({v!r}) must not be called for ipmi")
    monkeypatch.setattr(zipmi, "load_vendor", boom)

    from zipmi.cli.oem_cmds import cmd_oem_run
    import argparse
    # No cmd_name -> listing path: must not call load_vendor, returns 0.
    args = argparse.Namespace(cmd_name=None, data=[])
    rc = cmd_oem_run(args, "ipmi")
    assert rc == 0
    assert "Table G-1" in capsys.readouterr().out
```

- [ ] **Step 2: Run test to verify it passes for the listing path, then harden**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q -k load_vendor`
Expected: PASS — the no-cmd listing path returns before the send
block, so `load_vendor` is never reached. This guards the listing
path. Step 3 adds the guard the **send** path needs.

- [ ] **Step 3: Add the guard**

In `cmd_oem_run`, replace:

```python
    zipmi.load_vendor(vendor)
    with _open_session(args) as s:
        cc, resp = s.send_raw(netfn, cmd, data_bytes)
```

with:

```python
    if vendor != "ipmi":
        zipmi.load_vendor(vendor)   # standard cmds need no OEM table
    with _open_session(args) as s:
        cc, resp = s.send_raw(netfn, cmd, data_bytes)
```

- [ ] **Step 4: Run the full unit file**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q`
Expected: PASS (all tests so far).

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/oem_cmds.py tests/unit/test_ipmi_catalogue.py
git commit -m "feat(cli): skip load_vendor for ipmi catalogue (no OEM table)"
```

---

### Task 5: Register the top-level `zipmi ipmi` verb

`_add_vendor_parser` hardcodes `"OEM cmd name"` help. Add an optional
noun; register `ipmi` as a top-level verb (not in `VENDORS`, not under
`oem`).

**Files:**
- Modify: `zipmi/cli/oem_cmds.py` (`_add_vendor_parser` ~893–904; `add_oem_subparsers` ~907–919)
- Test: `tests/unit/test_ipmi_catalogue.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_ipmi_catalogue.py`:

```python
from zipmi.cli.oem_cmds import VENDORS
from zipmi.cli.zipmi import build_parser


def test_ipmi_is_not_an_oem_vendor():
    assert "ipmi" not in VENDORS


def test_ipmi_verb_parses_and_dispatches():
    parser = build_parser()
    ns = parser.parse_args(["ipmi", "Get Device ID", "0x01"])
    assert ns.cmd_name == "Get Device ID"
    assert ns.data == ["0x01"]
    # func is the cmd_oem_run closure bound to "ipmi"
    assert callable(ns.func)


def test_ipmi_verb_listing_no_args():
    parser = build_parser()
    ns = parser.parse_args(["ipmi"])
    assert getattr(ns, "cmd_name", None) in (None, [])
    assert callable(ns.func)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q -k ipmi_verb`
Expected: FAIL — `argument …: invalid choice: 'ipmi'` (no such verb
yet).

- [ ] **Step 3: Add the optional help-noun to `_add_vendor_parser`**

Replace the whole `_add_vendor_parser` function:

```python
def _add_vendor_parser(
    parent_sub,
    vendor_key: str,
    blurb: str,
) -> argparse.ArgumentParser:
    sp = parent_sub.add_parser(vendor_key, help=blurb)
    sp.add_argument("cmd_name", nargs="?",
                    help="OEM cmd name (substring match; omit to list)")
    sp.add_argument("data", nargs="*",
                    help="optional data bytes (hex like 0x01 or decimal)")
    sp.set_defaults(func=lambda a, v=vendor_key: cmd_oem_run(a, v))
    return sp
```

with:

```python
def _add_vendor_parser(
    parent_sub,
    vendor_key: str,
    blurb: str,
    cmd_noun: str = "OEM cmd",
) -> argparse.ArgumentParser:
    sp = parent_sub.add_parser(vendor_key, help=blurb)
    sp.add_argument("cmd_name", nargs="?",
                    help=f"{cmd_noun} name (substring match; omit to list)")
    sp.add_argument("data", nargs="*",
                    help="optional data bytes (hex like 0x01 or decimal)")
    sp.set_defaults(func=lambda a, v=vendor_key: cmd_oem_run(a, v))
    return sp
```

- [ ] **Step 4: Register the `ipmi` verb in `add_oem_subparsers`**

In `add_oem_subparsers`, immediately **after** the
`for vkey, vinfo in VENDORS.items(): _add_vendor_parser(top_sub, vkey, vinfo["blurb"])`
loop and **before** the `oem = top_sub.add_parser("oem", …)` line,
insert:

```python
    # Standard IPMI 2.0 (Table G-1) commands by name. A catalogue, not
    # an OEM vendor -> registered as a top-level verb only, never added
    # to VENDORS, so `zipmi oem` does not list it.
    _add_vendor_parser(
        top_sub, "ipmi",
        "standard IPMI cmd by name (omit to list Table G-1)",
        cmd_noun="IPMI cmd",
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ipmi_catalogue.py -q`
Expected: PASS (entire unit file green).

- [ ] **Step 6: Commit**

```bash
git add zipmi/cli/oem_cmds.py tests/unit/test_ipmi_catalogue.py
git commit -m "feat(cli): register top-level `zipmi ipmi` verb"
```

---

### Task 6: End-to-end against vbmc

**Files:**
- Modify: `tests/integration/test_vbmc_loopback.py` (append; reuses the existing `vbmc_dell` fixture and `main`)

- [ ] **Step 1: Write the failing test**

Append to `tests/integration/test_vbmc_loopback.py`:

```python
def test_ipmi_verb_send_device_id(vbmc_dell, capsys):
    from zipmi.cli.zipmi import main
    rc = main(["-H", "127.0.0.1", "-p", str(vbmc_dell),
               "ipmi", "Get Device ID"])
    out = capsys.readouterr().out
    assert rc == 0
    # name resolves from the spaced form; output prints the camelized
    # display name + wire address.
    assert "GetDeviceID" in out


def test_ipmi_verb_listing_needs_no_host(capsys):
    from zipmi.cli.zipmi import main
    rc = main(["ipmi"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Table G-1" in out
    assert "GetDeviceID" in out
```

- [ ] **Step 2: Run test to verify it passes**

Run: `python -m pytest tests/integration/test_vbmc_loopback.py -q -k ipmi_verb`
Expected: PASS (2 passed). Production code from Tasks 1–5 already
implements this; failure here means an earlier task regressed — stop
and investigate.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_vbmc_loopback.py
git commit -m "test(integration): zipmi ipmi end-to-end vs vbmc"
```

---

### Task 7: Documentation + doc-sync

**Files:**
- Modify: `README.md` (`zipmi verbs` block; `OEM discovery and usage` block — both inside `<details>` shutters)

- [ ] **Step 1: Add the verb row**

In `README.md`, in the fenced `zipmi verbs` list, add this line
immediately **after** the `raw      <netfn> <cmd> [byte ...]` line:

```
ipmi     [cmd-name [byte ...]]           # standard IPMI cmd by name; no args = list Table G-1
```

- [ ] **Step 2: Add an OEM-discovery cross-reference**

In `README.md`, in the `### OEM discovery and usage` section,
immediately **after** the code block that ends with the
`zipmi -H <bmc> oem supermicro UtilRestoreConfig` line, add this
paragraph:

```markdown
The standard IPMI 2.0 set has the same by-name UX — `zipmi ipmi`
lists Table G-1, `zipmi -H <bmc> ipmi "Get Channel Authentication
Capabilities" 0x01 0x04` resolves the name and sends the bytes you
supply (same raw-data model as `raw`/`oem`).
```

- [ ] **Step 3: Run the doc-sync guard**

Run: `python scripts/check_doc_sync.py`
Expected: `doc sync OK (N tests, attack catalog matches.)`, rc 0.
(The HTML `<details>` wrappers and the new lines do not affect its
substring/test-count checks.)

- [ ] **Step 4: Run the full test suite**

Run: `python -m pytest -q`
Expected: all pass. Note the new total (was 66). **If the printed
count differs from the `66/66 tests pass` / `66 passed` strings in
`README.md` and `docs/STATUS.md`, update those strings to the new
number** (Task adds ~8 unit + 2 integration tests → expect 76) — then
re-run `python scripts/check_doc_sync.py` to confirm rc 0.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/STATUS.md
git commit -m "docs: document `zipmi ipmi` verb + sync test counts"
```

---

## Self-Review

**Spec coverage:**
- Decision 1 (raw-bytes model) → Tasks 1/4/6 (no encoders; `send_raw` with user bytes via existing `cmd_oem_run`). ✓
- Decision 2 (OEM-identical matching) → Task 2 (locks `_find_cmd` behaviour). ✓
- Decision 3 ((netfn,cmd) scope only) → Task 1 (`_vendor_listing` built solely from `IPMI_CMD_NAMES`, which is the Table G-1 `(netfn,cmd)` map; RAKP/ASF pseudo-names live in other dicts, not iterated). ✓
- Decision 4 (top-level verb, not in VENDORS) → Task 5 (`test_ipmi_is_not_an_oem_vendor`, registration outside the VENDORS loop and outside the `oem` subparser). ✓
- Decision 5 (no mass rename; labels corrected) → Task 3 (title only). ✓
- Spec "Changes" 1–6 → Tasks 1 (changes 1,2), 3 (change 3), 4 (change 4), 5 (changes 5,6). ✓
- Spec "Testing" unit + integration → Tasks 1–6. ✓
- Spec "Doc-sync touchpoints" → Task 7. ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code; no "similar to Task N". ✓

**Type consistency:** Row dict keys (`name/priv/desc/live/missing/prefix/args/src`) identical across Task 1 (definition) and Tasks 3/4 (consumption). `_add_vendor_parser` signature gains `cmd_noun="OEM cmd"` (Task 5) with all existing callers using the default. `cmd_oem_run(args, vendor)` and `_vendor_listing(vendor)`/`_vendor_stats(vendor)`/`_print_vendor_listing(vendor)`/`_find_cmd(listing, query)` signatures used consistently. ✓
