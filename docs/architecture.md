# zipmi — architecture

Full design lives in `~/.claude/plans/fizzy-skipping-biscuit.md`. This doc is
the in-tree summary.

## Layer stack

```
UDP(623) → RMCP →┬→ ASF_PresencePing/Pong          (DSP0136)
                 ├→ IPMI15_Session → IPMI_Message → <CmdPayload>
                 └→ IPMI20_Session →┬→ RAKP1/2/3/4
                                    └→ IPMI20_Payload → IPMI_Message → <CmdPayload>
```

## Phasing

| Phase | Scope                                                           |
| ----- | --------------------------------------------------------------- |
| 0     | Scaffold + RMCP + ASF Ping/Pong                                 |
| 1     | IPMI 1.5 session, Message + checksums, top-20 spec cmds         |
| 2     | CLI MVP (raw/chassis/sensor/sel/sdr/lan/user/mc) over 1.5       |
| 3     | RMCP+ + RAKP + cipher suites                                    |
| 4     | OEM modules (dell first), `load_vendor()`                       |
| 5     | vbmc server (generic + dell + sm personas)                      |
| 6     | Fuzz harness — `sweep`, `rakp_mut` (CLI: `rakp`), `length`, `cipher_confuse` (CLI: `cipher`); all four wired |
| 7     | SOL, replay, oracle-diff CLI, QEMU CI                           |

## Module map

- `zipmi.scapy_ipmi.rmcp`          — RMCP framing
- `zipmi.scapy_ipmi.asf`           — ASF Ping/Pong
- `zipmi.scapy_ipmi.ipmi15`        — IPMI 1.5 session + Message
- `zipmi.scapy_ipmi.ipmi20`        — RMCP+ session + payload types
- `zipmi.scapy_ipmi.rakp`          — RAKP 1–4
- `zipmi.scapy_ipmi.crypto`        — cipher suite table, AES/HMAC helpers
- `zipmi.scapy_ipmi.commands`      — `(netfn, cmd) → Packet` registry
- `zipmi.scapy_ipmi.cmd_names`     — IPMI Table G-1 `(netfn, cmd) → name` lookup + `label_from_wire()` for trace dumps
- `zipmi.scapy_ipmi.colorize`      — ANSI byte-range colourer + ColorBrewer palettes (auto/pastel/set/dark) + COLORFGBG / OSC 11 background detect
- `zipmi.scapy_ipmi.{sensors,sel,sdr,sol}` — domain-specific cmd payloads
- `zipmi.scapy_ipmi.oem.{dell,supermicro,idrac9}` — OEM dispatch (opt-in via `load_vendor()`).
  - `dell_binary_names.py` carries the canonical (NetFn, cmd) → handler-symbol map RE'd from `T710-bmc/bin/fullfw`; overrides MD-author placeholder names ("(FW phase cmd)" → real Phase1/Phase2/etc.). 195/213 entries named.
  - `supermicro.py` ships `SM_TOP_CMDS` (7 incl. ATEN AlUpdate exfil) + `SM_SUBCMDS` (61) from the smcipmi RE work; `supermicro_smcipmi_names.py` overlays 153 OEM + 226 sub-cmds harvested by decompiling `SMCIPMITool.jar 2.30.0` (cfr) and walking `setCommandAndData((byte)NetFn<<2, (byte)Cmd, ...)` call sites. CLI listing merges both into a 422-row catalogue.
  - `idrac9_dispatch_generated.py` covers 271 static dispatch slots from the iDRAC9 firmware extract; 46 cross-reference to handler symbols via `idrac9_generated.py` (upstream RE doc). `idrac9_binary_names.py` overlays 277 names total from two sources: dynsym DF .text addr resolution (145), plus R_ARM_GLOB_DAT runtime-dispatch extraction across all `*.so.9.9.9` libs (132 more). Net: 277 of 349 known dispatch slots named; 72 still bound entirely at runtime via paths invisible to static analysis.
- `zipmi.scapy_ipmi.groups.{_registry,dcmi}` — IPMI Group Extension (NetFn 0x2C) name tables; auto-registered on import. DCMI 1.5 today; PICMG / HPM / VITA stubbed.
- `zipmi.core`                     — Session / Transport
- `zipmi.cli.zipmi`                — argparse entry point
- `zipmi.cli.oem_cmds`             — `zipmi <vendor>` / `zipmi oem` dispatcher (run OEM cmds by name)
- `zipmi.cli.groups_cmds`          — `zipmi <body>` / `zipmi groups` dispatcher (NetFn 0x2C Group Extension)
- `zipmi.vbmc.{server,state,handlers}` + `personas/` — virtual BMC
- `zipmi.fuzz.sweep` — NetFn × Cmd sweep with streaming output (CLI: `fuzz sweep`)
- `zipmi.fuzz.rakp_mut` — RAKP1 field mutation harness (CLI: `fuzz rakp`)
- `zipmi.fuzz.length` — IPMI 1.5 msg_length corruption (CLI: `fuzz length`)
- `zipmi.fuzz.cipher_confuse` — RMCP+ cipher-suite negotiation fuzz (CLI: `fuzz cipher`)

## Header convention

Every `.py` carries a top-of-file docstring with:

- WHAT — one-line purpose
- WHY — why this exists
- SUCCESS — how to know it works
- TARGET — which device/protocol/version
- BUILD/RUN — how to exercise it
- RELATED — pointers to specs, prior work, sibling files
