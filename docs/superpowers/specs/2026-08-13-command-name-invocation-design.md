# Command-name invocation & discovery — design

## Purpose

Let a user run any IPMI command by **name** without knowing NetFn numbers or the
exact spec spelling, and without falling back to `zipmi raw 0xNN 0xMM …`. Today
`zipmi ipmi <name>` does a substring match and curated verbs (`chassis status`,
`sel list`) cover the common path; this generalizes name-based invocation across
all 188 catalogued commands and adds keyword discovery.

Independent of implementing more commands: the resolver works off the existing
188-name catalog now; adding a decoder later just flips a command's status.

## Slug normalization

Canonical slug of any string:

1. Split CamelCase at lower→upper boundaries (`GetChassisStatus` → `Get Chassis Status`).
2. Lowercase.
3. Replace every run of non-alphanumeric characters with a single `_`.
4. Strip leading/trailing `_`.

So all of these map to `get_chassis_status`: `GetChassisStatus`,
`"Get Chassis Status"`, `get_chassis_status`, `GET-CHASSIS-STATUS`, `get chassis status`.

Both the catalog names and the user input are normalized through the same
function, so matching is case-, space-, dash-, and underscore-insensitive.

## Command index

At startup build one dict from `zipmi/scapy_ipmi/cmd_names.py` (all 188 commands):

```
slug -> { netfn, cmd, name, status }
```

`status` is derived, same truth as `docs/command-table.md`:
- `✓` decoded — `(netfn,cmd)` in `CMD_PAYLOADS`
- `⚡` raw/verb — has a wired handler or curated verb
- `✗` not implemented — neither

Building the index is a pure, cheap dict comprehension; no network.

## Resolution order (hybrid — curated verbs win)

Given the first CLI token:

1. **Curated verb** (`mc`, `chassis`, `sel`, `bridging`, …) → dispatch that verb
   with its own rich arg parsing. Always wins on collision.
2. **Exact slug** match in the index → run it.
3. **Unique prefix/substring** slug match → run it.
4. **Ambiguous** (>1 match, no exact) → print the candidate list, exit 2.
5. **No match** → error: `nothing matches "<tok>"; try 'zipmi search <term>'`, exit 2.

Exact always beats partial. Never auto-run when ambiguous — predictable in scripts.

## Entry points

- **`zipmi <slug> [bytes…]`** — top-level unified dispatch. When the token is not
  a curated verb, run it through the resolver. If the resolved command has a
  decoded handler, use it; otherwise **raw-by-name**: send the opcode with the
  trailing bytes as request data, print completion code + response bytes (decode
  the response if a decoder exists). Honors `--json`.
- **`zipmi ipmi <slug> [bytes…]`** — explicit form, same resolver (retained for
  clarity and back-compat).
- **`zipmi search <term>`** (alias `zipmi ipmi find <term>`) — keyword search over
  command name + subsystem + `netfn/cmd`. Prints one row per hit:
  `<slug>   0xNN/0xMM   [✓|⚡|✗]   <Name>`. Honors `--json` (array of records).

### Raw-by-name for unimplemented commands

A resolved-but-unimplemented (`✗`) slug at top level **runs raw-by-name** (opcode
+ trailing bytes, response as cc + bytes) rather than refusing — it is a strictly
better `raw` (no NetFn lookup needed). This was confirmed in design review.

## Ambiguity / candidate output

```
$ zipmi get_sel
"get_sel" is ambiguous — 3 matches:
  get_sel_info          0x0a/0x40   ✓   Get SEL Info
  get_sel_entry         0x0a/0x43   ✓   Get SEL Entry
  get_sel_time          0x0a/0x48   ⚡   Get SEL Time
(exit 2)
```

## Testing

Pure functions, no network:
- **slug normalization** — the Camel/space/dash/case/underscore cases all collapse
  to the same slug; mutation-provable (change the collapse and a case fails).
- **resolution** — exact match runs; unique prefix runs; ambiguous returns the
  candidate set; miss returns the not-found signal; a curated-verb token is never
  shadowed by a slug.
- **search** — a keyword returns the expected commands with correct status.

## Out of scope (YAGNI)

- Fuzzy / edit-distance / typo ranking. Exact-else-list only.
- Interactive y/n confirmation prompts.
- Shell (bash/zsh) tab-completion — deferred; adds install/maintenance surface.
- Changing how curated verbs parse their arguments.

## Coverage table doubles as the command directory

`docs/command-table.md` carries a **`Run as`** column (the slug), placed right
after `Name`, so the coverage map is also the directory of what to type:

```
| CMD  | Name               | Run as               | Spec § | Priv | zipmi | … |
| 04h  | Chassis Identify   | `chassis_identify`   | 28.5   | O    | ⚡    | … |
| 0Fh  | Get POH Counter    | `get_poh_counter`    | 28.14  | U    | ✗    | … |
```

The slug is derived from the catalog name by the same normalization, so the
column stays truthful to what the resolver accepts. It is generatable from
`cmd_names.py` (a small `python -m` helper can regenerate the column so it never
drifts).

### Slug collisions

Two catalog names can normalize to the same slug — notably **Broadcast Get
Device ID** and **Get Device ID** both → `get_device_id`. Rule: the slug resolves
to the **implemented** command; the other (always the `✗` broadcast variant here)
is simply not reachable by slug and stays runnable only via `raw`. Collisions are
rare and always involve an unimplemented twin; the resolver never has to choose
between two *implemented* commands with the same slug.

## Files touched

- `zipmi/cli/zipmi.py` — top-level dispatch fallthrough, `search` verb wiring.
- new small module (e.g. `zipmi/cli/resolve.py`) — slug normalization + index +
  resolution (isolated, unit-testable, no session).
- `zipmi/scapy_ipmi/cmd_names.py` — source of the 188-name catalog (read-only).
- `tests/unit/test_resolve.py` — new.
