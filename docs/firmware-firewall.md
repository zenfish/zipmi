# `firewall` — IPMI Firmware Firewall discovery

`zipmi firewall` walks the IPMI 2.0 **Firmware Firewall Configuration** discovery
commands (NetFn App `0x06`, spec §21) against a live BMC and interprets the result —
the machine-readable map of the BMC's command surface: what's *exposed*, what's
*lockable*, and what's currently *disabled*. Was `scripts/ipmi_firewall.py`; now a
first-class verb (`zipmi/cli/zipmi.py :: cmd_firewall`).

## What it walks

| Cmd | Name | Gives |
|---|---|---|
| `0x09` | Get NetFn Support | which NetFns the channel exposes |
| `0x0A` | Get Command Support | per-NetFn, which commands the firewall can control |
| `0x0B` | Get Configurable Commands | which of those can be disabled |
| `0x62` | Get Command Enables | current on/off state |
| `0x0C` / `0x63` | Sub-function Support / Enables | for group-extension NetFns (`0x2C`/`0x2E`) |

Each command code is resolved to a human name via zipmi's IPMI/OEM catalogs
(`lookup_cmd_name`). The support mask is what the vendor made firewall-*controllable* —
a superset of "configurable", a subset of "implemented". Mandatory commands
(Get Device ID, the firewall commands themselves) are implemented but **not** in the mask.

## Usage

```sh
zipmi -H <bmc> -U <u> -P <p> firewall                 # channel 0x0e (current) by default
zipmi -H <bmc> -U <u> -P <p> firewall --channel 0x01  # a specific channel
zipmi -H <bmc> -U <u> -P <p> firewall --probe         # send each cmd (empty) to ground-truth implemented (cc!=0xC1)
zipmi -H <bmc> -U <u> -P <p> firewall --subfn         # walk sub-functions for every named command
zipmi -H <bmc> -U <u> -P <p> firewall --json out.json # structured dump
```

Connection flags (`-H/-U/-P/-C/-p/-t/-I`) are the standard zipmi globals — cipher
auto-negotiates. The whole walk (Get NetFn Support → per-NetFn support/configurable/enables,
optionally per-command sub-functions and probes = potentially hundreds of queries) runs in
**one session**, so it amortizes the RAKP setup the same way `i2cscan` does rather than
re-authenticating per query.

## Reading the output

- `N in firewall table` — set bits in the support mask. On MegaRAC and others the firewall
  defaults the whole 0–127 range to "supported", so a large count is flagged
  `[mask coarse …]` and the trustworthy signal is the **named** subset.
- `named` — commands with a known IPMI/OEM name (real). `unnamed set-bits` are mostly the
  over-reported reserved codes; `--probe` grounds them (cc `0xC1` = not implemented).
- `DISABLED` / `<-- blocked` — in the support mask but cleared in Get Command Enables:
  a command the firewall is actively blocking. This is the audit-relevant column.
- OEM NetFns (`≥0x2E`) with no name catalog print a slot count instead of 128 `<OEM>` lines;
  map opcodes to the vendor's `.so` handler tables (see `docs/dell-command-table.md`,
  `docs/idrac9-command-table.md`).

## Where it fits

Between the two views zipmi already had: the *static* spec/vendor coverage
(`command-table.md`, `dell/idrac9-command-table.md`) and the *brute* "what responds"
(`fuzz sweep`). The firewall is the BMC's **own declaration** of its surface — the middle.
`--probe` reconciles declaration vs reality.

*Real capture: the `test_firewall.py` NetFn-support decode uses a Cray XD670 (MegaRAC) mask.*
