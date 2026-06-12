# Task: OpenBMC support for zipmi (2026-06-12)

Goal (from user, PHD research): add OEM support for OpenBMC vendors via the
existing plugin architecture; deep-dive OpenBMC; talk to the live QEMU
romulus target with zipmi.

## Done

### OEM plugin modules (the headline ask)
Nine OpenBMC vendor flavors, each a thin `oem/<v>.py` calling
`register(vendor, iana, {(netfn,cmd):name}, payloads)`:
- `intel.py` (343, 77 cmds incl. fw block + decoded payloads), `google.py`
  (11129, real NetFn 0x2E + IANA + 28 sub-cmds), `ampere.py` (40981),
  `facebook.py` (4337, iana=None on wire), `openpower.py` (2, alias `ibm`),
  `inspur.py`, `foxconn.py`, `wistron.py`, `nvidia.py` (group 0x3C → GROUP registry).
- `oem/openbmc.py` — umbrella manifest + `load()/load_all()`; `load_vendor("openbmc")`.
- `groups/sbmr.py` — SBMR boot-progress group 0xAE (auto-loaded like DCMI).
- Wired into `load_vendor` aliases (ibm/meta/fb) and the CLI `oem` verb
  (generic listing branch — adding a vendor = 1 module + 1 manifest row).
- Registry now tolerates `iana=None` (raw-NetFn vendors don't claim enterprise-id 0).

### Bugs found bringing zipmi up against live OpenBMC (all fixed + verified live)
1. **cipher-17 key derivation** (crypto.py): K1/K2 used `b"\x01"*len(sik)`
   → 32-byte const for SHA256 → wrong keys → every authenticated command
   silently dropped. Fixed to the spec's fixed 20-byte const. Verified vs
   ipmitool known-answer K1/K2 and phosphor-net-ipmid source. **This blocked
   ALL auth against OpenBMC** (it offers only cipher 17).
2. **UDP retransmit** (core.py): zipmi had no retry; OpenBMC netipmid has a
   race where the first encrypted message after RAKP4 can beat the integrity
   key install → dropped once. Added `retries=3` retransmit-on-timeout.
3. **cipher-zero false positive** (core.py + cli): the scan short-circuited
   on sessionless creds and printed VULNERABLE without sending a packet (even
   for dead/unroutable hosts). Replaced with `probe_cipher_zero()` that
   actually opens a cipher-0 session + runs a command.
4. **ASF pong OEM IANA** (asf.py): decoded big-endian → 3188785152; fixed to
   little-endian → 4542 (ASF/DMTF).

### Tests
`tests/unit/test_openbmc.py` — 17 tests (cipher-17 const + known-answer,
ASF endianness, cipher-zero guards, registry iana=None, all 9 vendor modules,
google envelope, nvidia group, sbmr autoload, umbrella). Full suite: **241 passed**.

### Research deliverables (in ~/phd/bmc/openbmc/)
- `OPENBMC_OEM_IPMI.md` — full per-source OEM command catalog (9 vendors +
  phosphor baseline, ~260 cmds, security rollup, fingerprinting).
- `SURVEY-OPENBMC.md` — internet prevalence: ~148 OpenBMC IPs (~0.32% of
  Redfish BMCs, 9th/last; pop is 49% iDRAC / 18% iLO / 13% Supermicro).
- `LIVE-QEMU-romulus.md` — live wire test, decoded device-id, gap analysis.

## Verified
- `zipmi -C 17 mc info / sel info / user list` against live romulus: 5/5 OK
  (Mfr 0, Product 0, FW 3.01 — matches ipmitool oracle).
- `scan cipher-zero`: correctly "not vulnerable" on BMC (status 0x04) AND dead port.
- `scan asf-ping`: oem_iana=4542.
- `zipmi oem` lists all 9 OpenBMC vendors; name resolution works.

## Not done / follow-ups
- Decoded Scapy payloads only for a few Intel/Google cmds; rest are name-only
  (raw passthrough still works). Codegen from OPENBMC_OEM_IPMI.md is a follow-on.
- vbmc OpenBMC persona (emulate an OpenBMC target) not added.
- Remote OpenBMC fingerprinting (Redfish /Managers/bmc probe) not wired into a
  zipmi verb yet — survey playbook documents it.
