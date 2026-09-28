# Task — Collapse long values across all OEM tables (2026-09-28)

- [x] Add one shared UTF-8 byte threshold for long field values in both OEM renderers.
- [x] Render long values as accessible native disclosures without changing search text.
- [x] Add a visible-row Expand all / Collapse all control with a real disabled state.
- [x] Regenerate every paired OEM reference and compact command table.
- [x] Add renderer interaction regressions and visually verify representative dense/sparse pages.
- [x] Run every generator, doc sync, focused/full tests, artifact sweep, and independent review.

### Review

- Values over 80 UTF-8 bytes now use native `<details>` disclosures in every operation and identity row field; short values retain their existing inline markup.
- Expand all / Collapse all affects length-based disclosures in visible rows only. It leaves Request/Response schema disclosures independent and becomes disabled gray when the visible result set has nothing to expand.
- Regenerated all eight paired references and compact tables: Advantech, Fujitsu, iDRAC9, iDRAC10, IEIT, Lenovo, MegaRAC/YAFU, and NVIDIA. Version is 0.6.7.
- Browser proof on the 950-row IEIT reference: all 3,714 long fields expand in 0.47–0.66 seconds and collapse in 0.84–0.90 seconds without page overflow; a one-row result with no long values disables the control.
- The independent review's initial quadratic toggle-state finding was fixed by coalescing state scans to one per animation frame; re-review found no remaining issues.
- Proof: 63 focused tests and all 2,385 repository tests pass; all nine generator checks, doc sync, Python compilation, and `git diff --check` pass. Artifact sweep reports `dirty=0`; strict mode retains pre-existing duplicate generated/build handles and the external orphaned KISS record.

# Task — Complete IEIT NF5468M6 MegaRAC OEM support (2026-09-28)

- [x] Pin firmware/rootfs/provider provenance and recover the complete registration denominator.
- [x] Reverse-engineer every top-level and selector-dispatched OEM contract, privilege, activation, and side effect.
- [x] Implement target-specific codecs, bounded named routes, and safety gates without conflating OpenBMC Inspur.
- [x] Capture safe live evidence on the zBMC IEIT target; do not run mutating commands.
- [x] Generate the paired command reference and compact command table in the shared house style.
- [x] Add focused closure/codec/CLI/doc tests and link the target from public documentation.
- [x] Run generator, documentation, focused/full-suite, independent-review, and artifact-provenance checks.

### Acceptance specification

- Firmware: NF5468M6 BMC 7.26.05 image SHA-256 `b7915aa4be2661d47d78cca6265dc11d8d06c23cc199e0ff80a2adc3ccd7c7d1`.
- Registration closure: 324 rows / 323 unique `(NetFn, Cmd)` addresses across AMI core, 39 enabled AMI plugins, IEIT PDK, PNM, and HPM OEM tables.
- Collision: preserve both providers for `0x30/0xe2`; do not silently overwrite one registration.
- Leaf closure: enumerate every statically recoverable selector/subcommand branch beneath those registrations and state any genuinely runtime-defined boundary.
- Contract closure: each operation records request/response fields and bounds, privilege, completion codes, activation, side effects, safety gate, binary/source evidence, and confidence.
- Execution: read-only operations may run normally; every mutating, disruptive, destructive, credential-bearing, or unresolved operation requires `--unsafe`; malformed requests fail locally.
- Documentation: generate both Standard v1 HTML views from the same catalog and expose IEIT separately from OpenBMC `inspur` and generic MegaRAC/YAFU.
- Validation: retain only safe live captures; generator freshness, focused tests, doc sync, full suite, artifact sweep, and independent review must pass.

### Review

- Closed all 324 firmware registration rows / 323 unique wire addresses across 86 AMI core, 97 enabled-plugin, 137 IEIT PDK, three Intel PNM, and one HPM OEM registrations.
- Exposed 950 unique named routes: 470 target-decompiled AMI NetFn `0x32` operations, 282 normalized IEIT PDK operations, six auxiliary contracts, and the platform/BIOS selector map. All 277 PDK selector evidence leaves are represented exactly once.
- Fixed the independent review's three findings: public-name collisions now use real wire identity, the encrypted-license route retains its one-byte minimum, and PNM/chassis field constraints fail locally. No internal route sentinel is public.
- Retained safe live proof only. Read-only probes confirmed the target identity and selected routes; the `0x30/e2` collision timed out and wedged IPMI, so it is documented as disruptive and gated. No mutating request was sent. The disposable guest was stopped and its run archived afterward.
- Paired HTML pages render 950 rows without page overflow; wide tables use their intended scroll container and 331 long safety notes remain collapsed by default.
- Proof: 16 focused tests and all 2,385 repository tests pass; all seven OEM reference generators, shared table generator, doc sync, JSON parsing, and `git diff --check` pass. Artifact sweep reports `dirty=0`; strict mode still flags the pre-existing Lenovo duplicate handle and external orphaned KISS record. The full suite retains two pre-existing Scapy deprecation warnings.

# Task — Collapse long OEM safety notes consistently (2026-09-28)

- [x] Render safety notes over 80 characters as native disclosures in the shared reference renderer.
- [x] Regenerate every checked-in OEM command reference that uses the shared renderer.
- [x] Add focused regression coverage for both inline and collapsed safety notes.
- [x] Run generator freshness checks, focused/full tests, documentation sync, and final diff review.

### Review

- Notes of 80 characters or fewer remain inline; longer notes use the existing native `Safety details` disclosure.
- Regenerated Fujitsu, iDRAC9, iDRAC10, Lenovo, MegaRAC/YAFU, and NVIDIA references. Advantech remained byte-identical because none of its notes exceeds 80 characters.
- Search opens a matching closed disclosure without closing disclosures the reader opened manually.
- Proof: all eight generator `--check` commands pass; 56 focused tests and 2379 full-suite tests pass; independent review found no issues.

# Task — Complete NVIDIA GB200 OpenBMC OEM support (2026-09-28)

- [x] Pin the exact GB200 firmware/provider provenance and close the OEM handler inventory.
- [x] Encode every NVIDIA OEM request/response contract, safety class, and named CLI route.
- [x] Add focused contract, CLI, generation, and documentation tests.
- [x] Generate the Standard v1 command reference and compact command table in the shared house style.
- [x] Link NVIDIA from the public OEM documentation index and keep generated counts synchronized.
- [x] Run focused tests, generators in `--check` mode, documentation/whitespace checks, and the full suite.
- [x] Review the final diff for the smallest coherent implementation and record proof below.

### Review

- Closed all eight registrations in the pinned GB200 provider; all have request/response codecs, Admin privilege, completion codes, activation, side effects, and bounded named routes.
- Both BIOS credential operations fail closed without `--unsafe`; real argparse/help execution and the fixed `0x01` selector are regression-tested.
- Preserved the 2026-07-22 live verifier-disclosure proof without retaining raw credential material. Current safe live probing was intentionally skipped because debby's launcher has unrelated local modifications and its NVIDIA VM was operator-stopped.
- Independent review found and fixed the missing NVIDIA argparse flag, type-1 partial hash overwrite, exception-only persistence error, and source-provenance overclaim.
- Proof: `23 passed` focused; `2379 passed` full suite; generator `--check`, `scripts/check_doc_sync.py`, JSON parse, and `git diff --check` pass. Ruff is not installed in this environment.

# ⭐ TOP PRIORITY (2026-08-14): per-OEM columns across the whole command table

## Task — Use generation-specific iDRAC6 document names (2026-09-27)

- [x] Rename the packaged firmware analysis to `idrac6-fullfw-ipmi-commands.md`.
- [x] Rename the compact table to `idrac6-command-table.md`.
- [x] Update parser defaults, regeneration instructions, tests, and every documentation link.
- [x] Confirm that no iDRAC6 command-reference exists yet.
- [x] Verify generation, focused tests, lint, whitespace, and documentation synchronization.

### Review

- The source and compact-table names now identify iDRAC6 explicitly, matching the iDRAC9/iDRAC10 namespace.
- No compatibility aliases were retained: these are repository-internal documentation paths, and all tracked consumers were updated atomically.
- iDRAC6 remains the only completed firmware dispatch inventory without a Standard v1 HTML operation reference; it is the strongest next documentation target.
- Proof: 220 focused iDRAC6 tests and all 2,375 repository tests pass; Ruff, whitespace, doc-sync, and generator-path checks pass.

## Task — Pin iDRAC6 firmware provenance (2026-09-27)

- [x] Locate every known `fullfw` copy and prove they are byte-identical.
- [x] Verify the ELF contains the documented 120-entry and 93-entry dispatch tables.
- [x] Record the firmware SHA-256 in the authoritative RE source.
- [x] Propagate the hash through both existing generated Dell outputs.
- [x] Run focused generation/tests and register the immutable firmware artifact.
- [x] Commit the verified provenance change.

### Review

- Four copies under the canonical research corpus, `_puff`, and the working directory are byte-identical: 1,760,176 bytes with SHA-256 `67f17aa14eda9e5d96b96825b93536a228db031acda90122eb353fba56dd3465`.
- Direct ELF reads recover 120 standard and 93 OEM registrations at the documented virtual addresses; the existing source has a separate seven-row late-OEM mapping discrepancy, deliberately left outside this provenance-only change.
- The source metadata is required by the generator and appears in both the generated Python registry and Markdown command table. Both outputs reproduce exactly.
- Artifact registry ID: `114fbd3b-139c-5edd-8961-cffe210ef1f7`. Focused proof: 220 passed; full suite: 2,375 passed; Ruff and whitespace checks pass.

## Task — Complete paired OEM documentation views (2026-09-27)

- [x] Remove the two retired mixed-case Advantech reference aliases and their generator outputs.
- [x] Convert Fujitsu iRMC S6 to OEM Command Reference Standard v1.
- [x] Generate compact command tables for Fujitsu, Lenovo, and corrected Advantech evidence.
- [x] Generate the iDRAC10 command reference and compact command table.
- [x] Generate the MegaRAC/YAFU command reference and make its compact table reproducible.
- [x] Rebuild the stale iDRAC9 command table and generate its command reference.
- [x] Verify every generator, denominator, artifact stamp, browser interaction, and full test suite.

### Preservation boundary

- Structured catalogs remain the source of truth; no rendered document is parsed to create another.
- Unknown payloads, activation, safety, or wire identity remain explicitly unknown.
- Compact tables describe registered identities; command references describe executable operations.
- `docs/command-table.md` remains the separate standard-IPMI implementation/live-support matrix.

### Review

- Published paired detailed/compact views for Advantech, Lenovo, Fujitsu, iDRAC9, iDRAC10, and MegaRAC/YAFU; retired three stale or incorrect Markdown inventories.
- The shared renderer keeps one safety vocabulary, comparable fields, incremental search highlighting, disclosure expansion, and a persistent top-docked horizontal scrollbar across all 12 pages.
- All generators pass `--check`; artifact stamps were refreshed; HTML tidy and doc-sync checks pass. Browser proof at 1400×900 confirmed every page's row count, overflow, search highlights, and visible scrollbar, plus hidden-evidence expansion and top docking without console errors.
- Full zipmi suite: 2,374 passed. zBMC's six touched documentation pairs are synchronized; its broader documentation contract still reports four pre-existing missing generated-Markdown links for Lenovo's local HTML-only references.

## Task — Shared OEM table interaction follow-up (2026-09-27)

- [x] Keep the horizontal scrollbar available while reading long operation tables.
- [x] Collapse verbose recovery evidence behind a native disclosure control.
- [x] Highlight search matches and reveal matches inside collapsed details.
- [x] Regenerate both shared-format references and verify behavior in a browser and test suite.

### Review

- The synchronized table scrollbar now docks to the viewport bottom only while the reader is below
  its normal position and the operations table continues below the viewport. Proportional syncing
  keeps the table aligned even when borders make the two scroll ranges differ slightly.
- Every operation's recovery evidence is collapsed behind a native `Recovered from` disclosure.
  Search uses rendered row text, highlights every matching fragment, and opens disclosures that
  contain a match; clearing or changing the search removes marks and closes only auto-opened details.
- Browser proof at 1400×900 confirmed the fixed scrollbar, both-direction endpoint sync, 335
  collapsed Lenovo evidence blocks, hidden request-field matches, recovery-evidence highlighting,
  automatic expansion, and zero page errors.
- Follow-up: highlight cleanup now normalizes the affected text nodes, so matches remain highlighted
  as a person types each character rather than only when a complete query is inserted at once.
- Follow-up: replaced the OS-native floating scrollbar with a persistent accessible track/thumb;
  macOS can no longer hide it, and pointer, keyboard, ARIA, filtering, and viewport docking were
  verified in Chromium.
- Follow-up: the floating control now remains at the viewport top, preserving its original position
  above the table instead of unexpectedly jumping to the bottom edge.

## Review — OEM Command Reference Standard v1 pilot (2026-09-26)

- Converted Advantech ASMB-787 to the shared light-theme renderer, semantic stylesheet,
  canonical lowercase HTML, stable compatibility redirects, fixed section/column order, and
  consistent filters.
- Replaced legacy effect jargon with six defined safety classes and separated request/response
  layout completeness, zipmi builders/parsers, execution policy, firmware availability, and live
  evidence. Response lengths and offsets now exclude the completion-code byte.
- Added exact firmware SHA-256/UUID provenance and reciprocal zBMC linkage. The legacy Markdown
  table is now a pointer to the canonical HTML rather than a second drifting reference.
- Proof: generator sync, focused 22-test suite, HTML structure/count assertions, JavaScript syntax,
  repository whitespace checks, and full-suite results recorded with the final commit.
- Follow-up: replaced the ambiguous Wire column with copyable `zipmi raw` commands and typed
  placeholders, bounded the operation table to the page width, restored heading scale after the
  Tailwind reset, simplified support labels, removed the rootfs hash, and explained the limited
  live-test denominator.
- Second follow-up: operation context now precedes the send command; all 192 supported named routes
  use readable `zipmi oem` syntax while 270 operation-only rows retain raw fallbacks. A synchronized
  top scrollbar makes hidden right-side columns discoverable.
- Third follow-up: reduced the title and section-heading scale; removed redundant scroll instructions
  and the reverse-engineering-only dispatcher table; clarified registration, privilege, and source
  labels; and recovered the exact two-byte `AMIGetRISConf` request plus its selector-dependent response.
  Proof: 22 focused tests pass; browser checks report 24px/18px headings, visible overflow scrollbar,
  synchronized horizontal scrolling, complete RIS request fields, and no secondary command table.

We now have full handler catalogs for several OEM stacks (ASMB-787/AMI,
iDRAC9, iDRAC6/Dell, OpenBMC ×9, Supermicro stub). `docs/command-table.md`
only shows two live-hardware columns (R710, X11SSZ) + one static column
(ASMB787). **Go over ALL the other OEMs and add a column for each** to the
standard-command tables in `docs/command-table.md`, filled from each stack's
real dispatch tables (static ground truth: ✓ handler present / ✗ absent),
same as the ASMB787 column just added.

- Source of truth per stack:
  - ASMB787 (AMI) — `docs/advantech-asmb787-command-reference.html` (DONE; corrected 187-row firmware dispatch catalog)
  - iDRAC9 — `docs/idrac9-command-table.md` (name-only; needs NetFn/cmd bytes
    from `G_asOEMIPMIReqeustHandleTable` — not yet cracked)
  - iDRAC6 — `docs/idrac6-command-table.md` (has NetFn/cmd — ready to columnize)
  - OpenBMC vendors — from `oem/*.py` (netfn,cmd) maps
- Also: compare a **Supermicro/Tyan AMI-MegaRAC** firmware against its own
  dispatcher. ASMB-787 `raw 0x32 0x66` is Administrator-gated; the former
  AMI-wide unauthenticated-backdoor claim came from swapped struct fields.

## Review — ASMB-787 OEM completion (2026-09-25)

### Follow-up — reference overview (2026-09-26)

- Added a generated top summary matching the Lenovo/Fujitsu references: 187 dispatch pairs,
  462 handler-proven operations, 81 fixed-width codecs, 33 live-backed reads, and the
  219-read-only/243-mutating-or-sensitive split.
- Reworked the initial summary after review: all 462 operations now carry visible safety tags,
  searchable plain-language purpose text, expandable byte-offset field maps, privilege,
  activation, completion codes, codec state, and evidence. Variable/union layouts retain their
  exact tokens and explicitly mark unresolved widths.
- Added combined text/safety filtering for operations, text filtering for the top-level dispatch,
  live result counts, and complete expandable indexes of the 157 mutating, 55 security-sensitive,
  and 31 destructive operations. Arbitrary flash/memory reads and credential-bearing reads were
  separated from genuinely destructive commands and remain `--unsafe`-gated. Closed dispatch coverage is no longer presented as complete
  structured-codec coverage or runtime plugin reachability.
- Generator sync and focused ASMB tests pass; full-suite proof is recorded with the final commit.

## Review — Fujitsu decode follow-up and zipmi 0.6.2 (2026-09-26)

- Refreshed the 232-operation iRMC catalog from the improved evidence: 102 decoded and 126
  partial outer leaves, with no wholly unknown outer leaf.
- Pinned the 50-case E0/04 maintenance table and 92-record backup/restore parameter table in
  the packaged source hashes and linked both from zipmi's reference.
- Built and installed the 0.6.2 wheel in an isolated environment; metadata reported 0.6.2 and
  the installed catalog contained 128 top-level names, 232 operations, and all seven source pins.

## Review — Advantech reference usability and safety correction (2026-09-26)

- Version 0.6.3 corrects the operation taxonomy and named-command gates uncovered while making
  the generated reference inspectable. Credential-bearing reads now require `--unsafe`; arbitrary
  flash/memory reads remain gated but are no longer mislabeled destructive.
- The generated HTML exposes exact high-impact identities, readable purposes, byte-level fields,
  per-operation and per-command safety tags, combined text/safety filters, completion codes,
  activation, codec state, evidence, and live status.

- Release version advanced to 0.3.4 after completing the 187/187 ASMB-787 operation surface and live read-only proof.
- Fresh post-reboot live validation exercised all 32 read-only codecs with safely synthesized requests: 26 CC00 reads and 6 expected target rejections, with no transport failures. Exact request bytes and observed CC/data are embedded in the contract source; one earlier redirected-media read brings total live-backed operations to 33.
- Exact-target core decompilation adds 210 selector operations across the remaining 79 pairs. The static denominator is now closed: all 187/187 dispatched commands have exact handler contracts, totaling 462 operations with 81 unambiguous codecs. `AMIGetFwVersion` preserves separate dispatcher and delegated-implementation hashes.
- Exact-target Plugin-B decompilation adds 132 selector operations across its complete 26-pair assignment, including password-key rotation, virtual-device power mode, and feature-gated PLDM BIOS operations. The generated catalog is now 252 operations / 108 pairs / 80 unambiguous codecs; Plugin-B safety split is 72 safe, 35 mutating, 22 security-sensitive, and 3 destructive.
- Exact-target Plugin-A decompilation now adds 52 operation contracts across 52 previously uncovered dispatch pairs; the generated catalog is at 120 operations / 82 pairs with 70 structured fixed-width codecs. Focused generator and unit proof: 22 passed.
- Canonical CSV contains 187 unique vendor NetFn/Cmd rows with exact firmware evidence, explicit semantic unknowns, confidence, and activation status.
- Native `advantech-asmb787` catalog exposes the complete named raw surface; aliases `advantech` and `asmb787` resolve to it; IANA 10297 is registered. Structured codecs are not claimed.
- Named execution enforces fixed dispatcher request lengths and requires `--unsafe` for destructive, variable-length, or schema-unknown commands; raw execution remains available.
- Generated HTML and Markdown references document every row: 92 static registrations, 85 feature-enabled plugin declarations with runtime registration unproved, and 10 feature-absent declarations. Type-8 secondary selector values remain explicitly unknown.
- Corrected the swapped privilege/request-length interpretation and withdrew the false ASMB unauthenticated/backdoor claims. YAFU no longer advertises universal availability or privilege.
- Proof: generator sync check passed; focused OEM/CLI suite passed (18 tests); repository doc sync passed after refreshing generated statistics.

## Review — Lenovo XCC public reference (2026-09-26)

- Added Lenovo to the README OEM section and linked the firmware-bound HTML reference from the coverage summary.
- Generated the reference from zipmi's 225-identity command catalog and 107 operation contracts; retained the 32-command safe live evidence beside it.
- Corrected RMCP+ `Session.granted_priv` to record the effective Set Session Privilege Level reply rather than the Open Session ceiling.
- Proof: documentation sync, generator rerun, HTML parse, and focused Lenovo/auth tests passed.
- Converted the reference to OEM Command Reference Standard v1: shared stylesheet and renderer,
  six-class safety vocabulary, consistent provenance/summary/filters/columns, copyable named or raw
  zipmi commands, compact headings, and a synchronized top scrollbar.
- Preserved the full closed inventory in one table rather than dropping catalog-only evidence: 107
  promoted contracts + 185 catalog-only decoded operations + 43 identity-only rows = 335 operations
  across all 225 prefix-qualified identities / 210 NetFn/Cmd addresses.
- Added generator `--check`, joined all 32 promoted-contract live observations plus three older
  catalog-only captures, retained the User-privilege destructive-reset warning, and gave Lenovo
  its own artifact identity.
- Review proof also covers open-ended named payload hints, exact selectors in multi-operation raw
  examples, high-impact safety labels, and firmware-handler evidence on promoted contracts.

## Review — OEM coverage table and 0.3.3 version (2026-09-25)

- Replaced the stale zero-command OEM summary with the live 2,176-command vendor inventory while retaining the useful iDRAC6 NetFn breakdown.
- Extended the existing stats updater and doc-sync gate to cover both aggregate markers and every vendor row.
- Bumped the single package-version source from 0.3.2 to 0.3.3; verification recorded in the commit handoff.

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

## 2026-09-28 — IEIT AMI NetFn 0x32 handler analysis review

- [x] Recovered all 183 unique registrations: 86 core and 97 plugin rows across 39 activated plugins.
- [x] Decompiled every registered target handler; resolved `AMIGetFwVersion` through its `libversionmgt.so.6.2.0` provider.
- [x] Normalized 470 operations with stable IDs, selector offsets/bytes, conservative auto-prefixing, request/response bounds, target-observed completion codes, and safety/effect classifications.
- [x] Kept 142 indirect/runtime-defined cases as explicit raw-exact boundaries instead of claiming an unproven older-firmware schema.
- [x] Verified unique registrations and operation IDs, complete per-row coverage, selector-prefix invariants, activation provenance, and JSON integrity.
- Evidence artifact: `zipmi/data/sources/ieit-nf5468m6-ami-netfn32-contracts.json` (`artifact_uuid` `0c40022e-8a43-49f4-a6f9-1281f6b7e4b2`).
