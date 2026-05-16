# Flexible Flag Position Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every global flag (`-H -p -U -P -A -I -C -t -v -d -n --palette`) valid at any token position in a `zipmi` command line.

**Architecture:** Two-pass parse. A globals-only `ArgumentParser` does `parse_known_args(argv)` and strips known globals from anywhere; the remainder (pure verb/action path) feeds the existing subparser tree, parsing into the same namespace. Globals on the command tree use `argparse.SUPPRESS` defaults so the second pass never clobbers pre-pass values.

**Tech Stack:** Python 3, argparse, pytest.

**Spec:** `docs/superpowers/specs/2026-05-16-flexible-flag-position-design.md`

**Deviation from spec (intentional, equivalent intent):** vbmc flags use *distinct* dests (`vbind`/`vport`/`vpersona`) and `cmd_vbmc_serve` is updated to read them (3-line change), instead of `dest=`-aliasing onto the global `port`. This fully removes the global-`port` vs vbmc-`port` shared-attribute ambiguity rather than merely hiding it. Same user-visible flags (`--vbind/--vport/--vpersona`), same outcome.

---

## File Structure

- **Modify** `zipmi/cli/zipmi.py`:
  - Remove `_add_conn_args` (lines ~97-121), `_TRACE` block (lines ~124-152), `_add_trace_to_leaves` def + call (lines ~1147-1182).
  - Add `add_globals(parser, *, suppress)` and `parse_cli(argv)`.
  - `build_parser()` top parser: replace `parents=[_TRACE]` + `_add_conn_args(p)` with `add_globals(p, suppress=True)`.
  - `vb_serve` flags renamed `--vbind/--vport/--vpersona` with distinct dests.
  - `cmd_vbmc_serve` reads `args.vpersona/args.vbind/args.vport`.
  - `main()` delegates parsing to `parse_cli`.
- **Create** `tests/unit/test_flag_position.py` — parser-level tests (no network).

No other files import the removed symbols (verified: grep confined to `zipmi.py`).

---

### Task 1: Two-pass global parsing

**Files:**
- Create: `tests/unit/test_flag_position.py`
- Modify: `zipmi/cli/zipmi.py` (remove lines ~97-152 helpers, ~1147-1182 leaf hack; edit `build_parser` top ~992-997; replace `main` ~1187-1198; add `add_globals`/`parse_cli`)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_flag_position.py`:

```python
"""
tests/unit/test_flag_position.py

WHAT  Global flags (-H/-d/etc.) must parse at any token position.
WHY   Users append -d/-H after a fully typed command; argparse
      subparsers normally forbid optionals after the verb.
"""
from __future__ import annotations

import pytest

from zipmi.cli.zipmi import cmd_mc_info, parse_cli


def test_global_before_verb():
    ns = parse_cli(["-H", "1.2.3.4", "mc", "info"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_global_after_action():
    ns = parse_cli(["mc", "info", "-H", "1.2.3.4"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_global_between_verb_and_action():
    ns = parse_cli(["mc", "-H", "1.2.3.4", "info"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_debug_appended_at_end():
    ns = parse_cli(["scan", "all", "-d"])
    assert ns.debug is True


def test_defaults_when_no_globals():
    ns = parse_cli(["mc", "info"])
    assert ns.port == 623
    assert ns.debug is False
    assert ns.host is None


def test_unknown_flag_hard_errors():
    with pytest.raises(SystemExit) as exc:
        parse_cli(["mc", "info", "--hots", "x"])
    assert exc.value.code != 0


def test_top_help_lists_globals():
    from zipmi.cli.zipmi import build_parser
    help_text = build_parser().format_help()
    assert "--host" in help_text
    assert "--debug" in help_text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_flag_position.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_cli'`.

- [ ] **Step 3: Remove old helpers**

In `zipmi/cli/zipmi.py` delete the entire `def _add_conn_args(...)` function (the block starting `def _add_conn_args(p: argparse.ArgumentParser) -> None:` through its last `p.add_argument("-t", "--timeout", ...)` line) and the entire `_TRACE` block (the comment `# Shared parent parser for verbosity flags...` through the final `_TRACE.add_argument("--palette", ... )` line, ending before `def _require_host`).

- [ ] **Step 4: Add `add_globals` and `parse_cli`**

Insert immediately above `def _require_host(args: argparse.Namespace) -> str:`:

```python
def add_globals(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Position-independent global flags.

    suppress=True => every default is argparse.SUPPRESS, so re-parsing the
    globals-stripped remainder never clobbers values the pre-pass set.
    """
    def d(real):
        return argparse.SUPPRESS if suppress else real

    parser.add_argument("-H", "--host",
                        default=d(os.environ.get("ZIPMI_TARGET")),
                        help="BMC IP/hostname (env: ZIPMI_TARGET)")
    parser.add_argument("-p", "--port", type=int, default=d(623),
                        help="UDP port (default 623)")
    parser.add_argument("-U", "--user",
                        default=d(os.environ.get("ZIPMI_USER")),
                        help="username (env: ZIPMI_USER). If neither -U nor "
                             "-P is given, requests are sent sessionless.")
    parser.add_argument("-P", "--password",
                        default=d(os.environ.get("ZIPMI_PASS")),
                        help="password (env: ZIPMI_PASS)")
    parser.add_argument("-A", "--auth", choices=AUTH_BY_NAME.keys(),
                        default=d("md5"),
                        help="auth type for IPMI 1.5 session (default md5)")
    parser.add_argument("-I", "--interface", choices=["lan", "lanplus"],
                        default=d("lan"),
                        help="lan = IPMI 1.5; lanplus = IPMI 2.0 RMCP+ "
                             "(default lan)")
    parser.add_argument("-C", "--cipher", type=int, default=d(3),
                        help="lanplus cipher suite (default 3 = "
                             "HMAC-SHA1+AES-CBC-128)")
    parser.add_argument("-t", "--timeout", type=float, default=d(3.0),
                        help="UDP timeout in seconds (default 3.0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=d(False),
                        help="log high-level events with timestamps (no hex)")
    parser.add_argument("-d", "--debug", action="store_true",
                        default=d(False),
                        help="-v + hex-dump every packet (incl. session "
                             "setup)")
    parser.add_argument("-n", "--no-color", action="store_true",
                        default=d(False),
                        help="disable ANSI colour in wire-trace hex output")
    parser.add_argument("--palette", default=d(None),
                        choices=["auto", "a", "pastel", "p",
                                 "set", "s", "dark", "d"],
                        metavar="{auto/a,pastel/p,set/s,dark/d}",
                        help="colour palette (default: auto — detects "
                             "terminal background)")


def parse_cli(argv: list[str] | None = None) -> argparse.Namespace:
    """Two-pass parse: strip globals from anywhere, then parse the
    verb/action remainder into the same namespace."""
    pre = argparse.ArgumentParser(add_help=False)
    add_globals(pre, suppress=False)
    ns, rest = pre.parse_known_args(argv)
    parser = build_parser()
    parser.parse_args(rest, namespace=ns)
    return ns
```

- [ ] **Step 5: Rewire `build_parser` top parser**

Find in `build_parser()`:

```python
    p = argparse.ArgumentParser(
        prog="zipmi",
        description="Scapy-based IPMI client.",
        parents=[_TRACE],
    )
    _add_conn_args(p)
```

Replace with:

```python
    p = argparse.ArgumentParser(
        prog="zipmi",
        description="Scapy-based IPMI client.",
    )
    add_globals(p, suppress=True)
```

- [ ] **Step 6: Remove the leaf-hack**

Delete the entire `def _add_trace_to_leaves(parser: argparse.ArgumentParser) -> None:` nested function (the comment block `# Add wire-trace -v / -d to every leaf subparser.` through the line `_add_trace_to_leaves(p)`), leaving `return p` as the next statement after the subparser wiring.

- [ ] **Step 7: Replace `main`**

Replace the body of `def main(argv: list[str] | None = None) -> int:` so it reads:

```python
def main(argv: list[str] | None = None) -> int:
    args = parse_cli(argv)
    try:
        return args.func(args)
    except IPMIError as e:
        print(f"IPMI error: {e}", file=sys.stderr)
        return 1
    except (OSError, socket.timeout) as e:
        print(f"transport error: {e}", file=sys.stderr)
        return 1
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_flag_position.py -v`
Expected: PASS — all 7 tests green.

- [ ] **Step 9: Commit**

```bash
git add zipmi/cli/zipmi.py tests/unit/test_flag_position.py
git commit -m "$(cat <<'EOF'
feat(cli): position-independent global flags via two-pass parse

Globals (-H/-d/etc.) now valid anywhere on the command line. Replaces
_add_conn_args + _TRACE parent + _add_trace_to_leaves hack with a single
add_globals() spec and a parse_cli() pre-pass. Unknown flags hard-error
with usage (exit 2).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: vbmc `v`-prefixed flags (collision removal)

**Files:**
- Modify: `zipmi/cli/zipmi.py` (`vb_serve` block ~1118-1124; `cmd_vbmc_serve` ~853-855)
- Modify: `tests/unit/test_flag_position.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_flag_position.py`:

```python
def test_vbmc_flags_renamed_with_v_prefix():
    ns = parse_cli(["vbmc", "serve", "--vport", "7000",
                    "--vbind", "0.0.0.0", "--vpersona", "dell_idrac6"])
    assert ns.vport == 7000
    assert ns.vbind == "0.0.0.0"
    assert ns.vpersona == "dell_idrac6"


def test_vbmc_no_port_collision_with_global():
    # -p is the global connection port; --vport is the vBMC listen port.
    ns = parse_cli(["-p", "700", "vbmc", "serve", "--vport", "7000"])
    assert ns.port == 700
    assert ns.vport == 7000


def test_vbmc_old_port_flag_rejected():
    with pytest.raises(SystemExit):
        parse_cli(["vbmc", "serve", "--port", "7000"])
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_flag_position.py -k vbmc -v`
Expected: FAIL — `ns` has no attribute `vport` (current flag is `--port`).

- [ ] **Step 3: Rename the vbmc flags**

Replace the three `vb_serve.add_argument(...)` lines for persona/bind/port with:

```python
    vb_serve.add_argument("--vpersona", dest="vpersona", default="generic",
                          help="generic | dell_idrac6 (default generic)")
    vb_serve.add_argument("--vbind", dest="vbind", default="127.0.0.1",
                          help="bind address (default 127.0.0.1)")
    vb_serve.add_argument("--vport", dest="vport", type=int, default=6230,
                          help="vBMC UDP listen port (default 6230)")
```

- [ ] **Step 4: Update the handler**

In `cmd_vbmc_serve`, find:

```python
        asyncio.run(run(persona_name=args.persona,
                        host=args.bind, port=args.port,
                        trace=trace, color=color))
```

Replace with:

```python
        asyncio.run(run(persona_name=args.vpersona,
                        host=args.vbind, port=args.vport,
                        trace=trace, color=color))
```

- [ ] **Step 5: Run to verify it passes**

Run: `python -m pytest tests/unit/test_flag_position.py -k vbmc -v`
Expected: PASS — 3 vbmc tests green.

- [ ] **Step 6: Commit**

```bash
git add zipmi/cli/zipmi.py tests/unit/test_flag_position.py
git commit -m "$(cat <<'EOF'
feat(cli): rename vbmc serve flags to --vbind/--vport/--vpersona

Removes the global -p/--port vs `vbmc serve --port` collision now that
globals parse at any position. Distinct dests; handler updated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Full regression + docs sync

**Files:**
- Modify (if stale): `README.md`, `docs/STATUS.md` (test counts; vbmc flag names)

- [ ] **Step 1: Run the full unit suite**

Run: `python -m pytest tests/unit tests/parsers tests/golden -v`
Expected: PASS — all pre-existing unit tests green + the new `test_flag_position.py` (10 tests).

- [ ] **Step 2: Run the vbmc loopback integration test**

Run: `python -m pytest tests/integration/test_vbmc_loopback.py -v`
Expected: PASS. If it spawns `vbmc serve` via CLI args, confirm it uses `--vbind/--vport` (update the test invocation to the new flag names if it used `--bind/--port`).

- [ ] **Step 3: Run the entire suite**

Run: `python -m pytest -v`
Expected: PASS — full suite green (was 80; now 80 + 10 new flag-position tests = 90, assuming no integration test required flag-name edits; adjust expected count if Step 2 edited a test).

- [ ] **Step 4: Sync docs if counts/flags changed**

Grep for stale references:

Run: `grep -rn "80 passed\|66 passed\|vbmc serve --port\|--bind\|--persona" README.md docs/STATUS.md`
For each hit: update the test count to the number `pytest` reported in Step 3, and change any `vbmc serve --port/--bind/--persona` examples to `--vport/--vbind/--vpersona`. If no hits, skip this step.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
docs: sync test count + vbmc flag names after flexible-flag-position

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- Truly-anywhere globals → Task 1 (`parse_cli` pre-pass) + tests before/after/between.
- Two-pass split parser approach → Task 1 Step 4.
- Unknown flag hard error exit≠0 → Task 1 `test_unknown_flag_hard_errors`.
- Remove `_add_trace_to_leaves` → Task 1 Step 6; `_TRACE`/`_add_conn_args` → Step 3.
- vbmc `v`-prefix + collision gone → Task 2 (intentional dest deviation documented in header).
- Help still lists globals → Task 1 `test_top_help_lists_globals`.
- Regression incl. vbmc loopback → Task 3.

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output.

**Type consistency:** `add_globals(parser, *, suppress)` / `parse_cli(argv)` signatures consistent across Tasks 1-2; vbmc dests `vpersona/vbind/vport` consistent between subparser (Task 2 Step 3) and handler (Task 2 Step 4) and tests.

**Known limitation (from spec, no task needed):** a global value starting with `-` needs `--password=-secret` form — pre-existing argparse behavior, out of scope.
