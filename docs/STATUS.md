# zipmi — overnight status

End-of-night snapshot of where this is. Use `git log --oneline` for the
play-by-play; this doc is the bird's-eye view.

## Phases done

| Phase | Scope | Commit |
|-------|-------|--------|
| 0 | RMCP + ASF Ping/Pong, repo scaffold, mandatory headers, MIT license | `f2fa059` |
| 1a | IPMI 1.5 Session + IPMB Message + checksums; sessionless Get Channel Auth Caps | `1103f77` |
| 1b | MD5 auth + Activate Session + Get Device ID end-to-end vs Dell | `340d541` |
| 2 | CLI MVP: `mc`, `chassis`, `sel info`, `raw`, `scan` | `83e2e46` |
| 3 | IPMI 2.0 RMCP+ / RAKP1-4 / cipher 3 (HMAC-SHA1 + HMAC-SHA1-96 + AES-CBC-128) | `56e248a` |
| 4 | More commands: `sensor list`, `sel list`, `sdr list`, `lan print`, `user list`, `mc selftest`, `mc guid`, `chassis identify`, cipher-zero scan | `163726e` |
| (docs) | Scapy-style interactive tutorial (`docs/tutorial.md`) | `e5c1e55` |
| 5 | Virtual BMC (`zipmi vbmc serve`) — asyncio loopback, generic + Dell personas | `8724911` |
| 6 | Fuzz harness — `zipmi fuzz sweep`, length-field corruption | `c2e60ff` |
| 7 | System Boot Options + OEM dispatch registry + Dell/SM modules | `0656676` |
| 8 | RAKP1 mutation fuzzer | `4d2f6c8` |
| 9 | Dell fullfw codegen — 192 entries from RE markdown | `6a47302` |
| 10 | `docs/dell-command-table.md` auto-generated from same parser | `d31a079` |
| 11 | doc-sync cleanup after codegen | `20ef102` |
| 12 | iDRAC9 handler catalog (313 entries) + Supermicro OEM expansion + Dell attack primitives | `23d5aea` |
| 13 | iDRAC9 dispatch-table codegen — 271 (NetFn, cmd, priv) tuples from rootfs ELF static parse | `c12aa52` (RE) + this commit |

## Tests

```
$ pytest tests/ -q
..................................................................       [100%]
80 passed in 2.91s
```

Eight integration tests + 72 unit tests covering RMCP / ASF / IPMI 1.5
checksums + auth code / RAKP HMACs + SIK derivation / OEM dispatch / Dell
fullfw codegen + iDRAC9 dispatch-table codegen + Dell attack primitives
+ BMC generation fingerprinting.

## Live verification (Dell PowerEdge T710 / iDRAC6 1.70 @ 192.168.0.23)

| Verb / probe | Result |
|--------------|--------|
| `zipmi scan asf-ping` | Pong, oem_iana=4542 (ASF), ipmi=yes |
| `zipmi scan auth-caps` | auth=[MD2, MD5, IPMI2.0], ext_caps=0x03 |
| `zipmi scan cipher-zero` | not vulnerable |
| `zipmi mc info` (lan / MD5) | manuf=674 fw=1.70 product=0x0100 gen="iDRAC6 (Monolithic)" — matches ipmitool |
| `zipmi -I lanplus -C 3 mc info` | same fields via RMCP+ / cipher 3 |
| `zipmi raw 0x06 0x01` | byte-exact match with `ipmitool raw 0x06 0x01` |
| `zipmi mc selftest` | Passed |
| `zipmi mc guid` | DELLX...5131 |
| `zipmi chassis status` | power=on |
| `zipmi sel info` | 41 entries, 7536 free |
| `zipmi sel list` | all 41 decoded, generator id + ts + sensor |
| `zipmi sdr list` | 126 records walked |
| `zipmi sensor list` | ~30 named sensors w/ readings |
| `zipmi lan print` | IP / mask / MAC / gateway / source=static |
| `zipmi user list` | 16 user slots, names + access bytes |
| `zipmi chassis bootflags` | valid=False device=no_override |
| `zipmi fuzz sweep --netfn 0x06` | **51 BMC responded**, 202 BMC rejected (0xC1), 0 errors, 3 skipped |

## Live verification (vbmc loopback, Dell persona)

```
$ zipmi vbmc serve --persona dell_idrac6 --port 6231 &
$ zipmi -H 127.0.0.1 -p 6231 mc info        # fingerprint = Dell
$ zipmi -H 127.0.0.1 -p 6231 -I lanplus mc info  # same via RMCP+
$ zipmi -H 127.0.0.1 -p 6231 fuzz sweep --netfn 0x06   # 8 impl, 0 errors
```

## Useful CLI surface

```
zipmi mc {info, reset cold|warm, selftest, guid}
zipmi chassis {status, power on|off|cycle|reset|soft --yes,
               identify [secs], bootdev <dev> [--yes],
               bootflags}
zipmi sel {info, list}
zipmi sdr list
zipmi sensor list
zipmi lan print
zipmi user list
zipmi raw <netfn> <cmd> [byte ...]
zipmi oem [vendor [cmd-name [byte ...]]]    # list vendors / OEM dispatch by name
zipmi {idrac6|idrac9|supermicro} [cmd-name [byte ...]]   # OEM shortcuts
# idrac6:     192 cmds (binary-RE'd from T710-bmc/bin/fullfw, r2)
# idrac9:     277 named / 349 known (46 RE doc + 99 dynsym addr-resolved + 132 R_ARM_GLOB_DAT runtime-dispatch)
# supermicro: 422 cmds — smcipmi RE (4 top + 61 sub + AlUpdate 0x3e×3) + SMCIPMITool.jar 2.30.0 decompile overlay (153 OEM + 226 sub)
zipmi groups [body [cmd-name [byte ...]]]   # IPMI Group Ext dispatcher (NetFn 0x2C)
zipmi dcmi [cmd-name [byte ...]]            # Group Ext shortcut (DCMI 1.5)
zipmi scan {asf-ping, auth-caps, cipher-zero, all}
zipmi fuzz sweep --netfn 0xNN [--rate Hz] [-v]
zipmi vbmc serve --persona <name> [--bind addr] [--port n]
```

Common flags: `-H -p -U -P -A {none,password,md5} -I {lan,lanplus} -C N -t T`,
or set `ZIPMI_TARGET / ZIPMI_USER / ZIPMI_PASS` env vars.

## Open follow-ons (not blocking)

* **X11SSZ live tests** — blocked: target 192.168.0.24 currently down.
  Populate the `?` cells in `docs/command-table.md` once back up. RMCP+
  cipher 17 (HMAC-SHA256) negotiation in particular is untested against
  modern silicon.
* **fuzz/cipher_confuse.py** — advertise N, send M; exercises cipher-suite
  validation strictness.
* **SOL** — payload type 0x01 + serial-over-LAN passthrough.
* **`zipmi diff <ipmitool args>`** — wraps ipmitool with `-vvv`, captures
  bytes, runs zipmi equivalent, byte-diffs both. Oracle for regressions.
* **`zipmi replay <pcap>`** — scapy `wrpcap`/`rdpcap` integration.

## Done since first STATUS.md draft

* OEM Dell codegen — `parsers/md_table.py` → 192 entries in both
  `oem/dell_generated.py` and `docs/dell-command-table.md`.
* `fuzz/rakp_mut.py` — RAKP1 mutation harness landed (commit `4d2f6c8`).
* iDRAC9 handler catalog — 313 named entries in `oem/idrac9_generated.py`,
  rendered to `docs/idrac9-command-table.md`.
* iDRAC9 dispatch-table codegen — 271 (NetFn, cmd, priv) tuples recovered
  by static parsing of three rootfs ELF .so libs (`liboemcmds`, `libdcmi`,
  `libosa`); cross-referenced with the handler catalog to humanize 46
  cmd names. `load_vendor("idrac9")` now populates the OEM registry.
  Source: `idrac9-firmware/dump_dispatch_tables.py` →
  `idrac9-firmware/idrac9-dispatch-tables.md` →
  `parsers/idrac9_dispatch_md.py` →
  `oem/idrac9_dispatch_generated.py` → `oem/idrac9.py`.
* Supermicro OEM expansion — 53 sub-cmds across NetFn 0x30/0x68/0x6E/0x70
  and 5 catalogued shell-injection primitives (paths in
  `supermicro/smcipmi-reversing/EXPLOITS.md`).
* Dell attack primitives — 11 static + 2 factory primitives in
  `attacks/dell.py`, documented in `docs/attacks-dell.md`.

## Where to start reading

1. `README.md` — what / why / quickstart.
2. `docs/architecture.md` — phase plan + module map.
3. `docs/tutorial.md` — scapy-style REPL walkthrough.
4. `docs/command-table.md` — IPMI G-1-style cmd × platform status grid.
5. `docs/ipmi15-notes.md`, `docs/ipmi20-rakp.md` — implementation gotchas.
6. `docs/vbmc.md` (TODO) — but `zipmi/vbmc/server.py` headers are decent.

Sleep well.
