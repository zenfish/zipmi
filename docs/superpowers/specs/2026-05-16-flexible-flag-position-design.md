# Flexible flag position — design spec

Date: 2026-05-16
Status: Approved (design); pending implementation plan
File touched: `zipmi/cli/zipmi.py` (+ `zipmi/cli/oem_cmds.py`, `groups_cmds.py` only if they attach globals — verify in plan)

## Problem

`zipmi` uses an argparse subparser tree. Global connection flags
(`-H -p -U -P -A -I -C -t`) are attached only to the top-level parser, so
they must precede the verb:

    zipmi -H 1.2.3.4 scan all      # works
    zipmi scan all -H 1.2.3.4      # FAILS today

Trace flags (`-v -d -n --palette`) currently work at top **or** at the leaf,
via a `_add_trace_to_leaves()` walk that re-adds them to every terminal
subparser. Connection flags get no such treatment.

User pain: target host is buried mid-command; appending `-d`/`-H` after a
fully typed command is rejected. User wants every global flag valid at **any
token position**.

## Decisions (locked with user)

1. **Scope: truly anywhere.** Globals valid at any position, including
   between verb and action (`zipmi mc -H x info`).
2. **Implementation: two-pass split parser** (approach A). `parse_intermixed_args`
   rejected — argparse forbids it with subparsers. Manual argv hoisting
   rejected — fragile value detection.
3. **Unknown flag → hard error + usage, exit non-zero.** A typo like
   `--hots` must not pass silently.
4. **Remove `_add_trace_to_leaves`** entirely. Pre-pass becomes the single
   source of truth for all globals (~40 lines deleted).
5. **vbmc flags get a `v` prefix:** `--bind→--vbind`, `--port→--vport`,
   `--persona→--vpersona`. Resolves the global `-p/--port` vs
   `vbmc serve --port` collision. Implemented via argparse `dest=` so the
   `cmd_vbmc_serve` handler body is untouched.

## Architecture

### Single global spec

New helper, replacing the split `_add_conn_args()` + `_TRACE` parent:

```python
def add_globals(parser, *, suppress: bool) -> None:
    d = argparse.SUPPRESS if suppress else None  # None = use real default
    # -H/--host, -p/--port, -U/--user, -P/--password, -A/--auth,
    # -I/--interface, -C/--cipher, -t/--timeout,
    # -v/--verbose, -d/--debug, -n/--no-color, --palette
    # ...each add_argument uses default=<real> when suppress=False,
    #     default=argparse.SUPPRESS when suppress=True
```

- **Pre-pass parser** calls `add_globals(suppress=False)` — owns the real
  defaults.
- **Command parser**: only the *top-level* parser `p` in `build_parser()`
  calls `add_globals(suppress=True)` — so `zipmi --help` documents globals
  and `zipmi -H x verb` still parses. Leaf/action subparsers do **not** get
  globals. `SUPPRESS` defaults mean parsing the globals-stripped remainder
  never overwrites values the pre-pass already set on `ns`.

### Data flow (`main`)

```python
def main(argv=None):
    gp = argparse.ArgumentParser(add_help=False)
    add_globals(gp, suppress=False)
    ns, rest = gp.parse_known_args(argv)        # strip globals from anywhere

    parser = build_parser()                     # command tree; globals SUPPRESS
    parser.parse_args(rest, namespace=ns)       # unknown flag -> error+usage, exit 2

    try:
        return ns.func(ns)
    except IPMIError as e: ...
    except (OSError, socket.timeout) as e: ...
```

`parse_known_args` claims every recognized global wherever it appears and
returns the rest. `rest` is the pure `verb [action] [positionals]
[subcommand-flags]` path. A genuine typo (`--hots`) is not a known global,
so it lands in `rest`; no subparser claims it; argparse emits
`unrecognized arguments: --hots` with usage and exits 2 — satisfying
decision 3 with stock behavior.

### Removed

- `_add_trace_to_leaves()` function and its call.
- `_TRACE` parent parser and `_add_conn_args()` (folded into `add_globals`).
- `parents=[_TRACE]` on the top parser; top parser instead gets
  `add_globals(suppress=True)` so `zipmi --help` still documents globals.

### vbmc rename

`vb_serve` subparser:

```python
vb_serve.add_argument("--vbind",    dest="bind",    default="127.0.0.1", ...)
vb_serve.add_argument("--vport",    dest="port",    type=int, default=6230, ...)
vb_serve.add_argument("--vpersona", dest="persona", default="generic", ...)
```

`dest=` keeps `cmd_vbmc_serve` reading `args.bind/args.port/args.persona`
unchanged. No other subcommand flag collides with a global — verified
inventory: `--yes --persistent --uefi --netfn --rate --cmd` vs globals
`-H -p -U -P -A -I -C -t -v -d -n --palette` (long `--cmd` ≠ short `-C`).

## Error handling

- Unknown flag anywhere → argparse `unrecognized arguments` + usage, exit 2.
- A global value beginning with `-` (e.g. password `-secret`) requires the
  `--password=-secret` / `-P=-secret` form. Pre-existing argparse behavior,
  unchanged; documented as a known limitation.
- `raw netfn cmd data...` (`nargs="*"`): globals are stripped before the
  `raw` subparser sees argv, so `zipmi raw 0x06 0x01 -H x` works — `-H x`
  pulled by pre-pass, `0x06 0x01` remain as raw data.

## Testing

Unit (tests/, pytest):

- Global at start / middle / end:
  `-H x mc info`, `mc info -H x`, `mc -H x info`, `scan all -H x -d`
  — all yield identical parsed namespace.
- vbmc rename: `vbmc serve --vport 7000 --vbind 0.0.0.0 --vpersona dell_idrac6`
  sets bind/port/persona; `-p 700 vbmc serve` sets the *connection* port,
  not the vBMC listen port (collision gone).
- Unknown flag hard error: `mc info --hots x` exits non-zero, stderr has
  `unrecognized arguments`.
- Help discoverability: `zipmi --help` lists all globals. Per decision 4,
  leaf help (`zipmi mc info --help`) no longer lists `-v/-d/-n/--palette`
  (the leaf hack is deleted); assert globals absent from leaf help and
  present in top-level help.

Regression:

- Full existing suite green (currently 80: 8 integration + 72 unit).
- vbmc loopback integration (`tests/test_vbmc_loopback.py`) green with
  renamed `--vport`/`--vbind` flags.

## Out of scope

- Reordering/renaming any non-vbmc subcommand flag.
- Changing connection defaults or handler logic.
- argparse abbreviation policy (`allow_abbrev`) — leave at default.
