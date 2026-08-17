# ⭐ TOP PRIORITY (2026-08-14): per-OEM columns across the whole command table

We now have full handler catalogs for several OEM stacks (ASMB-787/AMI,
iDRAC9, iDRAC6/Dell, OpenBMC ×9, Supermicro stub). `docs/command-table.md`
only shows two live-hardware columns (R710, X11SSZ) + one static column
(ASMB787). **Go over ALL the other OEMs and add a column for each** to the
standard-command tables in `docs/command-table.md`, filled from each stack's
real dispatch tables (static ground truth: ✓ handler present / ✗ absent),
same as the ASMB787 column just added.

- Source of truth per stack:
  - ASMB787 (AMI) — `docs/advantech_ASMB787-command-table.md` (DONE, column added)
  - iDRAC9 — `docs/idrac9-command-table.md` (name-only; needs NetFn/cmd bytes
    from `G_asOEMIPMIReqeustHandleTable` — not yet cracked)
  - iDRAC6 — `docs/dell-command-table.md` (has NetFn/cmd — ready to columnize)
  - OpenBMC vendors — from `oem/*.py` (netfn,cmd) maps
- Also: pull a **Supermicro/Tyan AMI-MegaRAC** firmware and re-run
  `oem-handler-lineage.md` to test whether `raw 0x32 0x66` restore-defaults is
  an AMI-wide backdoor (see that doc's open follow-up).

---

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

### Research deliverables (author's private research library)
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

## 2026-08-13 — Standard IPMI command build-out (read phase)

Goal: implement more of the 188 standard IPMI commands (was 63 done). Skip only
ICMB (NetFn 0x02 — nothing to test on). Zoo is disposable (snapshot=on → reset
via `vbmc <box> restart`), so writes/destructive are testable later.

Coverage-map work first: added the 33 missing standard commands to
docs/command-table.md (true denominator = 188, was tracking 157), a "Run as"
slug column, and per-NetFn "N done" summaries. Bidirectional audit: 0 under/over.

Read phase — 25 commands implemented (63 → 88 done), 4 batches, each
implement→test-live→flip-table-row→commit:
- Chassis (2): caps (0x00), poh (0x0F)
- App (6): global-enables (2F), acpi (07), sysinfo (59), payload support/version/
  instance (4E/4F/4B)
- Storage+Transport (5): sdr alloc/time (21/28), sel alloc/utc-offset (41/5C),
  lan stats (0x0C/04)
- Sensor (12): threshold/hysteresis/factors/type/event×2 (27/25/23/2F/29/2B),
  device-SDR×3 (20/22/21), PEF caps/config/last-event (10/13/15)

Highlights: sensor thresholds cook raw→engineering units via the EXISTING
sdr_full linearization (megarac P_12V verified 10.79–13.85 V). Suite 2005 pass.
Versions 0.2.10 → 0.2.13, all pushed.

### Remaining (paused before this phase)
- Write phase (no --yes per policy; verify by read-back): Set* twins for the
  above, Set Channel Access, Set PEF Config, Set SEL/SDR Time, FRU write, etc.
- Destructive (reset between via vbmc restart): Cold/Warm/Chassis Reset, Set
  Channel Security Keys, Clear SEL, SEL/SDR Add/Delete, Platform Event Message.
- Inert-on-zoo (implement, assert cc): serial PPP/callback, forwarded commands.
- Naming/resolver feature (spec approved, deferred): slug dispatch + `search`.
