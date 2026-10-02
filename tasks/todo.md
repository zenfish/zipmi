<!-- z-artifact: 1eb9bf8a-7cb1-472d-b49b-5999b9e99e61 -->
# Task — Complete Supermicro X10 support and X10→X14 genealogy (2026-09-30)

- [x] Pin the exact X10 firmware and provider provenance; prove the complete top-level and nested OEM dispatch denominator.
- [x] Recover every request/response layout, privilege, completion code, activation condition, side effect, and safety boundary without inheriting unproved X11/X12/X13 behavior.
- [x] Implement a distinct firmware-bound `supermicro-x10` target with bounded codecs and local safety gates while preserving the existing cross-generation `supermicro` interface.
- [x] Build a machine-readable X10↔X14 capability genealogy and risk classification: retained, reframed/renamed, behavior-changed, X10-only/dropped, and X14-new.
- [x] Generate X10 command-reference and command-table HTML plus a human-readable genealogy/risk document in the shared Standard v1 style.
- [x] Cold-boot the clean X10 zBMC deployment, capture exclusively non-mutating named-route evidence, and stop the guest afterward.
- [x] Run focused/full tests, generator/doc-sync checks, artifact verification, browser checks, independent review, and push all completion commits.

## Acceptance specification

- Bind all claims to the exact 32 MiB X10 FW 3.93 image and every contributing executable/library hash.
- Treat the target `OEMCmdTable` and all reachable child dispatchers as the denominator; do not equate the existing generic Supermicro name corpus with active X10 registrations.
- A named route is runnable only when its exact wire framing and safe bounds are recovered. Mutating, disruptive, destructive, credential-bearing, and unresolved operations require `--unsafe` or remain unrunnable.
- Genealogy matches normalized purpose, data flow, backend, and side effect before command number/name. Ambiguous ancestry remains explicit rather than forced into a one-to-one match.
- Every X10-only capability records whether X14 demonstrably dropped it, replaced it outside IPMI, or merely lacks evidence. Risk notes distinguish attack-surface removal from loss of defensive/diagnostic functionality.
- Live work uses the clean detached zBMC deployment recorded in `HOSTS.md`, sends no mutating request, preserves run evidence, and leaves QEMU stopped.

## Review

- Bound the result to X10 BMC 3.93 image SHA-256 `9bd3fbe8ddb8ee8e0f7d96ee37c810cef99d6c9f9566ddd13dca7ea455204214`, rootfs SHA-256 `f414a4dc447a4bea09374398f47caca0112a35cd5f61030f19712634659c67fd`, and `/lib/libipmi.so` SHA-256 `128d486c2de83d7e5dfddc0a25f74142f0c3fe265567ad4b1221c8defdbe3d07`.
- Reconciled all 91 executed `OEMCmdTable` registrations and 286 direct/nested operations. Explicit request bounds replace textual number inference; routes with mutation, sensitive effects, unresolved upper bounds, or target-unbounded reads require `--unsafe` (17 default-safe, 269 gated).
- Generated the paired Standard v1 reference/table and X10→X14 genealogy: 89 retained, 36 renamed/reframed, 11 behavior-changed, 138 X10-only/dropped, 85 X14-new, and 13 repurposed rows. Browser checks confirmed 286 rows, eight live markers, unique public names, and no body overflow.
- Cold zBMC run `20261001T053123Z-94da7b2a-be2f-4b7e-92ec-08ffc1290d86` reached READY in 234 seconds. Eight exact read-only named routes were captured over authenticated RMCP+; no mutating request was sent. The guest stopped cleanly and retained evidence SHA-256 `c3a4588ff0fefb91a4c705d6536f894ab43bf3e5dbb4a2f4d581f172863730a2` was copied into the run archive.
- Registered contract artifact `806a7e1c-ee03-545c-9fdc-11f70621f0d2` and live-evidence artifact `8d284d10-2a79-523f-bc5c-03b60a38048f`. Artifact sweep reports no dirty tracked artifacts; remaining silent drift/duplicate/orphan findings predate this task.
- Verification: focused X10 tests pass (12); full repository suite passes (2,424, with two existing Scapy deprecation warnings); generator freshness, doc sync, JSON generation, and `git diff --check` pass. Independent final review found no remaining correctness or safety issue.
- Follow-up review (2026-10-01): corrected the genealogy denominator by removing one synthetic parent-dispatcher row and including all 11 delegated Intel Node Manager operations. Identity-set conservation now proves X10 286/286 and X14 244/244 with mutually exclusive counts: 89 retained, 36 renamed/reframed, 11 behavior-changed, 12 repurposed, 138 X10-only/dropped, and 96 X14-new. Clarified that X14 `ReadMemoryCmd` reads the BMC AST2600 SoC register address space through the BMC Linux `/dev/mem`, never host DRAM. Replacement contract artifacts: X10 `8fd00c94-aef8-58e7-b265-66fd15a47f49`; X14 `f6fdcb11-2898-5356-9008-f9aa6ecb46eb`. Focused tests pass (34), full suite passes (2,424), both generators and doc sync pass, and independent re-review found no issue.

# Task — Close vanilla OpenBMC, then Supermicro X14 (2026-09-28)

## Phase 1 — Vanilla AST2600 OpenBMC

- [x] Pin the exact zBMC image/source provenance and prove the complete IPMI registration denominator.
- [x] Prove the absence of vendor OEM providers and registrations statically and from retained safe live evidence.
- [x] Represent vanilla OpenBMC explicitly in zipmi without conflating it with the nine-flavor `openbmc` umbrella.
- [x] Generate paired Standard v1 HTML reference/table pages that document the zero-OEM closure and standard/DCMI boundary.
- [x] Add discovery, CLI, generator, documentation, and zero-row rendering regressions.
- [x] Verify generators, browser behavior, doc sync, focused/full tests, artifacts, and independent review; commit phase 1 before X14.

### Phase 1 acceptance specification

- The zero-command claim must be tied to the exact firmware artifact and upstream source revision, not inferred from manufacturer ID 0 alone.
- Static provider/config inventory and the existing exhaustive live sweep must agree: no raw OEM NetFn or IANA-group handler is registered.
- `openbmc` remains the vendor-flavor index; the vanilla target must not load or advertise the 130 commands from unrelated vendor providers.
- Both generated pages must remain useful with zero rows: provenance, denominator, method, boundary, sources, disabled Expand all, and no fake commands.

## Phase 2 — Supermicro X14

- [x] Pin X14 firmware/provider provenance and close the complete registration and selector denominator.
- [ ] Resolve every remaining Partial request/response layout and semantic field/action detail.
- [x] Add bounded codecs and safety-gated named routes where contracts are sufficiently recovered; keep unresolved parent/mutation paths disabled or unsafe-gated.
- [x] Obtain exclusively non-mutating live reachability evidence for the corrected named selector routes; retain the older broad dispatch run separately with its explicit RAS caveat.
- [x] Generate paired Standard v1 HTML reference/table pages and public documentation links.
- [x] Run focused/full verification, artifact registration, browser checks, and independent review for the current milestone.

### Phase 2 acceptance specification

- Bind every claim to BMC image SHA-256 `8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792`, rootfs SHA-256 `d9767ced6fc5301ae02d1fb918314bc1c182c6de4baac2376b3914a0a1eb8afa`, and each contributing provider ELF.
- Reconcile the primary provider's 68 real registrations: 52 OEM/group identities and 16 standard-command overrides. Wrapper-mediated registrations must not be discarded, and wrapper bodies must not be double-counted.
- Reconcile all five target providers: 116 executed registrations / 115 unique wire identities, including 66 OEM/group-extension identities (52 primary, three RAS, and 11 delegated Intel Node Manager).
- Expand every statically recoverable selector beneath multiplexed handlers into a named operation. Keep top-level registrations, selector operations, standard overrides, and delegated Intel Node Manager commands as distinct counts.
- Document provider ownership explicitly: Supermicro primary, RAS, Intel Node Manager, and standard Sensor/SDR/Storage overrides. Do not duplicate Intel NM commands already owned by `openbmc-intel` or count standard overrides as new OEM commands.
- A route is runnable only when its exact request framing and safe bounds are recovered. Read-only operations may run normally; mutating, disruptive, destructive, credential-bearing, or unresolved operations require `--unsafe`.
- Live validation is limited to non-mutating requests. Retain completion-code evidence showing that primary, RAS, DMTF-group, and Intel NM handlers are reachable through RMCP+ forwarding, and stop the disposable guest afterward.
- Generate both Standard v1 HTML views from one structured catalog, preserving unknowns instead of inferring contracts from names or strings.

### Review

#### Phase 1 — Vanilla OpenBMC

- Bound the result to zBMC image SHA-256 `11b89cbb7a4b129529de26ff0b80030f1f7bdfb0e206a4a5207bd6d55a13c908`, upstream OpenBMC commit `5d179dab3c66c8b89e059eeb17b038a2beb435d3`, and build `20260717214914`.
- Recovered 81 static standard/DCMI registration call sites from five provider payloads, with zero OEM call sites, no vendor provider, and no JFFS2 override. Historical runtime handler counts from an older full image are deliberately excluded.
- Fresh zBMC run `20260929T002237Z-e63d50b0-0ecd-47e2-b425-d5196e8565a9` returned CC `c1` for all 4,864 bounded OEM probes with no alternate completion codes or transport errors, then stopped cleanly.
- Kept `zipmi oem openbmc` as the nine-flavor vendor-provider index. Vanilla remains standard IPMI/DCMI only and does not advertise those 130 unrelated OEM commands.
- Generated both Standard v1 zero-row pages. Chrome showed `0 of 0` and disabled gray Expand all controls on each page with the intended table-local horizontal overflow.
- Independent review found and verified fixes for static-call-site wording, current-versus-historical runtime provenance, the sibling-repository artifact path, and README grammar. Focused tests pass (`25 passed`); full suite passes (`2,386 passed`); generator freshness, JSON parsing, doc sync, Python compilation, and whitespace checks pass. Artifact sweep reaches `dirty=0`; strict mode retains pre-existing duplicate handles and an external orphaned KISS record.

#### Phase 2 — Supermicro X14

- Closed provenance to BMC image `8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792`, rootfs `d9767ced6fc5301ae02d1fb918314bc1c182c6de4baac2376b3914a0a1eb8afa`, and all five provider ELFs; reconciled 116 executed registrations / 115 wire identities, 66 OEM/group identities, and the hidden selector census.
- Added 22 individually named CM Provision child routes with local operand checks; kept its parent route unrunnable. Fixed the eight unsafe labels, recovered request/response bounds, corrected DCMI record order, and added the exact big-endian 16-bit CM response codec. Unrecovered layouts/actions remain marked Partial rather than inferred.
- Generated 244 detailed operation rows and 116 registration rows. Current contracts supersede `001eba16-182a-58ce-85ef-610509da11b2`, `394b506a-4311-579b-be8b-7b956733018b`, `bcfe54b0-6f4b-5e42-b8c7-a013e9ce08e4`, and `b08d69f5-2a9d-5993-be4e-a41e7a82afc7` as `b6b01e08-aa1f-5e20-9541-11fa042e10ad`; dispatch evidence is `26cdea4a-d4ff-55a8-a9c3-d859ddf77af2`. The evidence is explicitly not wholly non-mutating: empty RAS 0x32/0x23 reached `RasSetData`; no further live probes were sent.
- Verification for the current milestone: focused X14 tests pass (10); repository full suite passes (2,400). Fixed the unrelated `test_user_matrix_json_against_vbmc` startup race by retrying only `ConnectionRefusedError` for a bounded 10 seconds; integration tests pass (2/2). Doc sync, generator freshness, browser checks, artifact registration, and final independent code/docs review pass.
- Follow-up source review corrected PSU `0x79` from state-changing to read-only: its path uses getters/SMBus reads, forwards no extra write bytes, and returns identity-string slices for selectors D0–DF/E0–ED/F0–F6. The docs now disclose possible device-specific read-to-clear behavior. NVMe `0x6c` now records its lockdown D4 gate and exact response ceiling (216 bytes). Focused tests (10), generated-doc freshness, doc sync, and the full suite (2,400) pass.
- Further static analysis closed the `SetIPProtocolStatus` IF_Mode values and six compatibility no-ops (including TDM), with no-op routes now accurately classified as read-only. Broadcom HDD bitmap response `0x4c` now documents both 256-bit maps and the two zero-filled padding regions within its 80-byte body; the second map’s backend meaning and several Broadcom property-to-offset maps remain Partial. Focused X14 tests (10), generator freshness, doc sync, and whitespace checks pass.
- Corrected CM Provision child names and D-Bus call mappings where provider xrefs are exact; reclassified `0x20` (`upBackupGoldenImage`), `0x21` (`eraseImage`), and `0x85` (`clearRaProvision`) as state-changing/destructive, with regression coverage that `0x85` requires `--unsafe`. Child `0x30` now names all six contributing D-Bus reads while keeping per-bit meanings Partial. Focused X14 tests (10), generator freshness, doc sync, and whitespace checks pass.
- Selector 2 of `OEMGetPowerConsumption` now records its three exact JSON pointer sources while retaining Partial for their unknown wire packing. Full repository suite passes (2,400); no new live requests were issued.
- Closed `OEMGetADCValues` scaling from the primary ELF literal: output is `u8(((int64_t)((Value / 2.5) * 1023.0)) >> 2)`. At that checkpoint, 34 primary operations still carried semantic unresolved notes; response-field Partial status is tracked separately. Focused tests and generated references pass; this is not full X14 completion.
- Closed `SetFPLEDControl`'s lookup bytes from the exact pinned provider: inputs 0..3 select `6f 74 6f 63` from a PC-relative address inside an RTTI string; handler writes `(old & 0xc7) | value`, affecting bits outside 3..5. Kept it state-changing/unsafe-gated and documented the raw effect rather than assigning guessed LED names.
- `GetLinkStatusCmd`'s external `libsmci` helpers are now pinned/decompiled: `UtilGetLinkInfo` composes mode, active interface, four-byte `LAN_MII_INFO`, and three-byte NCSI status. At this stage, exact wire-to-member assignment remained to be reconciled (closed in the 2026-09-29 review below).
- Reconciled `GetLinkStatusCmd` byte order against the primary handler and pinned `libsmci` helper: the wire response is NCSI middle/high/low, dedicated speed/presence/link/property bytes, active interface, then IF mode. The byte-6 D-Bus property identity and NCSI bit labels remain unresolved. Added a byte-order regression assertion; generated reference and focused tests pass.
- IPv6 child `0x09` operation 2's provider/helper flow is now exact: a required 16-byte record loses its three control bytes, leaving bytes 3..15 as a 13-byte vector; pinned `translateIpv6ToStr` zero-pads its rounded temporary buffer and passes the resulting 16 bytes to `inet_ntop`, so the translated address ends in three zero bytes (not an over-read). Updated both generated docs and regression coverage. Operation-1 fields/property map and operation-2 byte-1/mode-0-byte-2/prefix/property semantics remain unresolved. No live request sent.
- `OEMRequestCOT` is now mapped from the corrected ELF VA: operation 1 sets `xyz.openbmc_project.State.BMC.RequestedBMCTransition` to `...Transition.Reboot` at `/xyz/openbmc_project/state/bmc0`, requesting a BMC reboot; the legacy parameter and optional tail are ignored. The endpoint had appeared unresolved because the earlier analysis mixed Ghidra-rebased and ELF addresses. Updated paired docs/tests; D-Bus failure-to-IPMI mapping and the handler-name acronym remain unknown. No live request sent.
- Closed Broadcom logical-drive `0x52` offsets 11–14 using exact consumer PC-relative literals plus `BroadcomLDdbus::createDbus` member registrations. Closed HDD `0x4d` flag-byte sources using consumer literals and producer getters; preserved the separate unresolved property at offset 46. Added producer/member and bit-extraction provenance plus regression assertions.
- Corrected OOB `DLOOBDataReadyCheck` (`0x0a`): its file-type argument is ignored and it always returns fixed payload byte 0; no readiness lookup occurs. `UploadOOBData` now documents the exact accepted selector set, little-endian argument packing, `system()` outcomes, and empty success body. `ClearConfigOption` documents the three statically proven action masks without guessed subsystem labels. `FakeSensorData` now documents its ignored request byte, accepted lengths, u16 parsing, and fallback-write behavior while preserving unresolved setter binding. Current primary semantic gaps: 32.
- `OEMSetGetLinkConf` (`0x63`) operation 1 was a false mutation gate: handler decompilation proves it only reads `SysLockdownEnable`, returning `0xD4` when enabled and empty success otherwise. Reclassified the selector read-only; operation 2's external helper is pinned to constant `0x59`. Individual capability-bit labels remain Partial.
- Cross-checked Broadcom responses against the pinned `storagebroadcom` producer. Subsequent raw ARM literal and producer-member correlation resolved `0x52` offsets 11..14 as `StripeSize`, `NumDrives`, `SpanDepth`, and `State`; `0x4d` offset 146 as `useSSEraseType`, `ISECapable`, and `sanitizeType`. The `0x4d` property at offset 46 remains unidentified.
- **2026-09-29 checkpoint (superseded):** Partial semantics/layouts and exclusively non-mutating runtime evidence were still outstanding at this point; later review entries record their closure.

#### Review — 2026-09-30 live route validation

- Live testing exposed a four-family catalog association error: child maps previously labeled `0x68`, `0x51`, `0xad`, and `0x70` actually dispatch on wire commands `0x70`, `0x68`, `0x51`, and `0xad`, respectively. Static PC-relative global tracing proved the complete rotation; `0xa0` was already correct.
- Rekeyed all 123 affected selector operations and the 22 CM Provision child routes at the canonical catalog layer. Top-level registrations remain unchanged because their wire commands and registered handler symbols were already correct.
- Safe zBMC run `20260930T225207Z-56f75a49-1b7e-479e-a1f7-6737c59b6d00` validated named SSL, Provision, IPv6, link, smart-power, total-budget, and license queries plus a deliberately short `0x51/0xd6` dispatch proof. No mutating request was sent; the guest stopped cleanly after 32m21s and was not restarted.
- Evidence: `docs/evidence/20260930T-supermicro-x14-safe-live-validation.json`, artifact `b2521984-8503-5e08-b60c-7773a8ad7d15`. The tested zipmi revision was `d63ba59`; this review commit records the final documentation and provenance.
- Final contract artifact `3687ce16-b26d-58d1-8bae-2fef2643d85d` (SHA-256 `9a8d42e26c1b95d8fbd9cd1f8b234a8bfbd5434c73a64ca6bf91e27406bf4d54`) supersedes stale catalog record `b6b01e08-aa1f-5e20-9541-11fa042e10ad`.

#### Review — 2026-09-29

- Corrected `0x63` safety and `0x4d`/`0x52` Broadcom mappings/provenance; generated references and added CLI/contract regression checks. Static evidence only; no live BMC request.
- Verification: focused X14 tests 12 passed; unit suite 2,383 passed; generator freshness, doc sync (2,402 catalogued tests), and `git diff --check` pass. The full suite's loopback integration tests could not bind UDP in this sandbox (`PermissionError`); prior run had 2,387 pass, 2 failed and 12 setup errors for that reason.
- Artifact registration could not be refreshed in this restricted workspace. Current local contract SHA-256: `03ea85b081b87e82f6f98c657c81ddb8ee2707c31b0bad441adfb63ebbb61c64`; registered UUID `b6b01e08-aa1f-5e20-9541-11fa042e10ad` still describes an older hash.
- Follow-up semantics closed or narrowed `GetUIDStatus` (derived `(result & 0x30) != 0` boolean), power selector 2 wire packing (Hour u16 then Day/Week packed u32), PSU EntityManager routing, and the misleading `OEMRemoveLighttpd` handler (lockdown read only). OOB transfer bounds/results and the exact 25 accepted `ClearConfigOption` masks are now documented. Broadcom mappings add `FwState == 1` bitmap semantics, `LinkSpeed`, compact logical-drive property offsets/ArrayRef, and corrected compact-drive offsets/flags/serial span. CM Provision now records exact child behaviors and high-impact 0x54/0x55 CPLD/AC-cycle effects. Compact Broadcom drive offsets now include the exact selector-derived byte, Array entries, FreeSize, and FirstFreeSize; only the CoercedSize multiplier remains unknown. `GetOOBFileStatus`/`ClearOOBFile` now document proven file-type paths; the former's `fwrite` is correctly scoped to debug logging. Corrected CAT-error SET to accept any present u8; NVMe docs now include proven D-Bus interfaces/actions and GET field offsets. Primary semantic notes remaining: 31; response layouts and non-mutating live evidence still require separate closure.
- Latest verification: focused X14 tests 12 passed; `scripts/check_doc_sync.py` reports 2,402 tests; reference generator freshness and `git diff --check` pass. No live BMC request was sent.
- Full `pytest -q`: 2,388 passed; 2 failed and 12 errored because this sandbox denies loopback UDP bind (`PermissionError` in existing integration fixtures). These are environmental, unrelated to X14. Focused X14 tests and doc sync pass.
- Artifact registration could not be refreshed in this restricted workspace. Registered UUID `b6b01e08-aa1f-5e20-9541-11fa042e10ad` still describes an older hash.
- NVMe GET subcommand 0 now records the constant byte and both unnamed split-u16 property writes at offsets 1–4 and 17–19; labels remain unknown. Focused tests (12), reference freshness, doc sync, and whitespace checks pass; no live BMC request was sent. Current local contract SHA-256: `cf901149924ce47b6c4a4dddf018ceaeaf65682579c152e55ce2ff0243e8dcba`.
- `GetPowerStatus` is now tied to Chassis `CurrentPowerState` at `/xyz/openbmc_project/state/chassis0`, not Host state; the pinned provider compares `PowerState.Off`/`.On` and encodes them as 0/1. The catalog and generated reference are corrected; primary unresolved semantic notes: 30. Focused tests (12), generator freshness, doc sync, and whitespace checks pass; no live BMC request was sent. Current local contract SHA-256: `9f6a72df0cf6346737a2724d25c584d4bd162429e6e280730d5099bb9ea5657e`.
- `OEMSSLCertificateStatus` now documents the helper-proven `server.pem` X.509 parse flag, `notBefore`/`notAfter` values, exact GMT `strftime` text format, NUL separators, and that private-key status is not tested. Pinned helper provenance: `libsmci.so.0.0.1`, build ID `38315acbaaf0c6a44dec5675d4707b6f3843d235`, SHA-256 `3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf`, function `0x6a4fc`. Primary unresolved semantic notes: 29. Focused tests (12), generator freshness, doc sync, and whitespace checks pass; no live BMC request was sent. Current local contract SHA-256: `3e72882096f7c83fdc935c50b21423934ab282a5e17387112ce0d42bceee0b14`.
- `EnableOOBDataBuffer` is now resolved from its exact leaf assembly: maps physical `0x1e6e2000`, reads the u32 at `+0x180`, sets bit `0x02`, and always returns empty success even when open/map fails. Safety remains state-changing/lab-only. Primary unresolved semantic notes: 28. Focused tests (12), generator freshness, doc sync, and whitespace checks pass; no hardware query or mutation was performed. Current local contract SHA-256: `41c5bc06a85a0281da4b54fc045370261423f51c750f1fed42689d11b3f42650`.
- `GetBRCMHDDBitmap` now labels `FwState == 1` as the strong cross-source inference `MR_PD_STATE_UNCONFIGURED_BAD (0x01)`: the pinned storage provider uses the `MR_PD_STATE_*` names, and upstream Linux's MegaRAID header supplies the numeric value. The target numeric declaration remains absent, so the catalog preserves that limitation and the primary semantic note. No live request was sent. Focused X14 tests (12), both generated-page freshness, doc sync (2,402 tests), and whitespace checks pass. Current local contract SHA-256: `be66a74b767e4e0b5452bbfb45422562500398377413707b704e59b108f310d3`.

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

## 2026-09-29 — X14 continuation review

- `OEMGetCMProvision` child `0x21` now records the pinned `smci-provision-mgr` selector-to-MTD map (BMC/BIOS backup, golden, and staging partitions) and preserves the backend's result caveat: the method can return 1 on logged erase-failure paths, so the IPMI byte is not an erase-success indicator. Added regression assertions; no live BMC request was sent.
- Follow-up disassembly resolves the BIOS Staging side effect to D-Bus `Properties.Set` targeting `xyz.openbmc_project.fwinfo.FwInfoManager.stagingBIOS` at `/xyz/openbmc_project/fwinfo`; the Set value remains unknown. The same pass narrows `getOTPKey` evidence: helper failures and record gate are documented; a byte-to-integer stream conversion suggests decimal ASCII rendering but remains explicitly unproven as the returned string. No live BMC request was sent.
- `OEMRequestCOT` review confirmed the endpoint/action remains unassignable from the target binary; its effect wording now describes the fixed method-call construction without claiming a known COT action. Added CLI safety/encoding regression for the exact minimal `2d 01 00` request (`--unsafe` required); no live request was sent.
- `LicenseFileAction` now records the pinned `libsmci` helper evidence for mask 5: flag 4 has precedence over flag 1; the helper returns 4/1 only when the respective generic OOB hook succeeds, otherwise 0. No product-license labels are inferred; they are absent from the retained binary. Regression checks added.
- `OEMGetSetBBP` completion-code prose now identifies its target-proven `0xD4` cause as `SystemLockdownEnable == true`, rather than incorrectly calling it insufficient privilege. The exact parameter/value names remain unavailable; the body is still proven to do no BBP read or write.
- CM Provision children `0x86`/`0x87` now include matching-daemon evidence for OTP helper arguments, temporary-file handling, bounded `fgets`, and the possible retained newline on the serial string. The key conversion itself remains explicitly unresolved. Generated docs and regression assertions updated; no live BMC request was sent.
- `OEMGetPSUInfo` now documents each request wire byte; its apparent address is only a high-nibble gate, and `GetPSURaw` receives the command byte then read length. The matching `smci-pws` daemon is retained; command/result behavior remains unresolved (see the 2026-09-30 review below).
- `OEMGetSetNVMeSSDParameters` SET values map to exact action methods `Locate`, `Dislocate`, `setButtonEnabled`, `RedLed`, and `Remove` (0–4). GET subcommands `0xff` and `2` are fully mapped from the provider's ARM call/store sequence. `0xff`: `LocateStatus`, `Presence`, and `LastPresence` u16le at offsets 0, 2, and 4; zero-filled tail 6..11. `2`: `LocateStatus`, `Presence`, `Remove`, and `RemoveBeforeButton` u32le values split into low/high u16 halves at (0/8), (2/10), (4/12), and (6/14).
- GET subcommand 1's 215-byte record is now fully accounted for: the handler zero-fills it, mapped properties include ClassCode/VendorId, identity, link, power, manufacturer, temperature, NSS-present flag/value, SmartWarning, and PDLU, and every other byte remains zero. Static analysis also found an 8-bit clipping bug: page offsets >215 can cause an out-of-bounds read/copy from BMC memory. zipmi's named route now rejects offsets >215; raw IPMI remains available. This does not fix firmware.
- GET subcommand 0 byte 8 is now named exactly `Ver`, resolved from the ARM PC-relative pointer to the substring at ELF pointer `0x001b7798` within `BIOSVer`; the provider compares it at `0xadd04` and stores the type-1 value at byte 8 at `0xadd1c`.
- Provider SET value 4 attempts D-Bus method `Remove`, but the exact retained `smci-nvme` daemon registers only `Locate`, `Dislocate`, `RedLed`, `isLocate`, and `setButtonEnabled` on the action interface. Its `Remove` string is a status property; no target-backed path ties the daemon's separate eject/MCTP release flow to this method. On this image the call has no matching registered method; physical removal/eject semantics remain unproven.
- `GetLinkStatusCmd` response byte 6 is mapped to the exact `AutoNeg` D-Bus property; the three packed NC-SI bytes are also closed: response offsets 0/1/2 carry speed/duplex, Link Flag, and Auto-Negotiate Flag. The helper's `0xF` speed nibble selects Extended Speed and Duplex bits 31..24. Evidence combines `libsmci.so.0.0.1` ARM instructions (SHA-256 `3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf`) and DMTF DSP0222 v1.2.0 Table 51.
- `GetServiceStatusCmd`'s two `isServiceActive` targets are now exact: `com.Supermicro` (14-byte literal prefix) and `com.Supermicro.hii.service` (26 bytes). The returned bitmap's bits 1 and 3 are labeled to the respective checks; static evidence is the target provider's callsites `0x000dcd64` / `0x000dcdc4` and `.rodata` literal at `0x001b16e8`.
- `FakeSensorData` now has exact setter/property semantics: the primary request reading is a u16 write to `com.Supermicro.sdr` / `com.Supermicro.sensor` / `fakevalue`; only when that fails, the handler writes request byte 0 as a bool to `isfake`. The ARM calls at `0x00097818` (variant tag 3/u16) and `0x000978e8` (variant tag 0/bool) and literal pointers prove the distinction.
- `OEMReportDebugMessage` now resolves both file operations to `/usr/share/log/3068db.log`. For type 5 with a present byte, it reads if present, zero-pads or truncates to 256 bytes, prepends the request byte while discarding the prior last byte, and rewrites the buffer; otherwise it is a successful no-op. Access/read and write path loads resolve to the same literal.
- The `OEMSetGetLinkConf` mask `0x59` was re-audited against the retained target and focused public-source searches. `PltLanSpeedSupport()` is only `mov r0,#0x59; bx lr`; neither this binary nor the retained sources contain a bit schema. Individual bit labels remain an explicit artifact boundary; keep the exact raw mask and do not borrow older firmware's different operation mapping.
- `OEMGetVMDeviceStatus` is now fully mapped: response bytes 0/1/2 are VirtualMedia1/2/3; inactive is `0xff`; active URLs ending in `.ima` or `.img` yield 0, and other active URLs yield 4. Provider assembly confirms the suffix branches and append values; the handler reads `Active` and `ImageURL` from the exact VirtualMedia interfaces. No live request was sent. Focused X14 tests now 13 pass; generator freshness, doc sync (2,403 tests), and `git diff --check` pass. Primary semantic unresolved count: 23. Contract SHA-256: `d75d9e9362bc07fb32df70c69cd091a603269722c429977767902cb3714e1c4f`.
- `GetBRCMCompactSpecificHDDInfo` offset 47 is now resolved as `(CoercedSize u64 * UserDataBlockSize u16) >> 30`, encoded u32le only when both inputs are nonzero. ARM PC-relative addressing resolves `UserDataBlockSize` exactly at `0x001a2b9c`; the paired `CoercedSize` literal is `0x001a2b90`. Focused X14 tests (13), reference freshness, doc sync (2,403 tests), and whitespace checks pass. Primary semantic unresolved count: 22. Contract SHA-256: `9c5c72558730f4ce586846ae7953efb881f9b01db10395381957f067130dd106`.
- `GetBRCMCompactSpecificLogicalDriveInfo` bytes 0..3 are `(Size u64 * userDataBlockSize u16) >> 30`; bytes 4..10 map to the exact target properties. The related LSI MegaRAID SAS-IR MIB v1.22 is documented as a cross-source inference for PRL/SRL values, not an X14-proven enum; RLQ remains unmapped. Focused X14 tests (13), generator freshness, doc sync (2,403 tests), and `git diff --check` pass. Primary semantic unresolved count: 22. Contract SHA-256: `551f19bcd63fa0ef156aff5686e2f70ce95f662bdddff1f246960cc04da8fea2`.
- `OEMGetSetCATError` is now fully resolved: the service is `xyz.openbmc_project.Settings`; the handler returns one byte for GET, no payload for successful SET, and `0xD4` when locked or when the property read fails. `GetOOBDataStatus` now names the mutating type groups (1, 2, 8, 12 are path-status checks; 17–22 and 24 append a checksum byte to source and derived destination files) while retaining its lab-only gate pending exact paths. `ClearConfigOption` now proves the `0x01000000` effect removes and recreates `/var/configuration/selstatus` at 65536 bytes. Focused X14 tests: 13 passed; generated reference/table freshness, doc sync (2,403 tests), and `git diff --check` pass. Primary semantic unresolved count: 21. Contract SHA-256: `96d1f8a855a81325ed1cbe03bde8ea3ba04e249b779458129c45d069e0ecc305`. No BMC request was sent.
- `GetOOBDataStatus`'s full 26-key type→path table is now recovered from the initializer and matched to handler tree lookups. This closes exact accepted IDs, type-12 null-path response, paths for types 1/2/8/17–22/24, file-size/nonempty response meanings, and the `%s%s` + `_chksum` sidecar behavior; the command stays lab-only because it appends to source and sidecar files. Focused X14 tests: 13 passed; generator freshness, doc sync (2,403 tests), and `git diff --check` pass. Primary semantic unresolved count: 20. Contract SHA-256: `0b84a351a9ee3154d21be6f33169ef2ba016857258580e710bb9c597d884a892`. No BMC request was sent.
- `ReportDownloadStatusToBMC` type 1 now names both exact cleanup paths (`/tmp/HII/boot_restore_setting` and its `.json` companion), proven by the handler's PC-relative string loads. Its indirect callback map remains unresolved. Focused X14 tests: 13 passed; both generated-doc freshness, doc sync (2,403 tests), and `git diff --check` pass. Primary semantic unresolved count remains 20. Contract SHA-256: `cadcf5d088f6b1b0425ec174727b1f85489f3ef28ec551cdca9c933055b18a24`. No BMC request was sent.
- No live BMC request was sent.
- Prior checkpoint verification: focused X14 tests 12 passed; reference freshness, doc sync (2,402 tests), and `git diff --check` pass. Contract SHA-256: `09ffdd7673b72378572b8a1e056b87a306c8ef5815b3b1951836b58eb10b0fb7`.
- Review (2026-09-29): recovered the 28-entry `FileActionTable` callback mapping and complete 26-slot OOB type/path map. Closed semantic gaps for ApplyFileCommand, ReportDownloadStatusToBMC, UploadOOBDataDone, GetOOBFileStatus, and ClearOOBFile; ClearOOBFile resets provider availability flags rather than deleting files. MMBI's exact byte-vector bounds, leading-byte validation, D-Bus methods, and 8-byte GET result are now documented; only daemon-private encryption/hash semantics remain unknown. Focused X14 tests: 14 passed; generated references current; doc sync (2,404 tests) and `git diff --check` pass. Catalog-wide semantic unresolved count: 15. No live BMC probes were sent.
- Review (2026-09-29): closed `UploadOOBData` with the shared 26-slot type→path map and exact `mem -f` template/address/count semantics; closed `PrepareFileDownload` by tracing its type-byte packing to the worker's `0x80 + type` `FileActionTable` lookup (17 named save callbacks; unmapped types call nothing). Narrowed `OEMRequestCOT` to an evidence-backed but unresolved D-Bus endpoint boundary. Corrected BBP's stale mutation-only runnable label: the handler checks lockdown and performs no BBP read/write, so zipmi now routes it as read-only. The matching `storagebroadcom` binary proves `UNCONFIGURED_GOOD=0`; `FwState==1` as `UNCONFIGURED_BAD` remains cross-source inference. Both X14 docs regenerated. Focused X14 tests: 18 passed; generator freshness, doc sync (2,407 tests), and `git diff --check` pass. Primary semantic unresolved count: 13. No live BMC probes were sent.
- Review (2026-09-29): closed CM Provision child `0x00/A=4` and child `0x01` against the provider's exact `doProvisioning` call and the matching rootfs `smci-provision-mgr` backend: one-byte start/reject result, asynchronous provisioning worker, RoT event `0x12`. The outer command remains unsafe-gated. Regenerated both reference and compact table; focused X14 tests (18), generator freshness, doc sync (2,408 tests), and whitespace checks pass. The aggregate `OEMGetCMProvision` note remains Partial for other operand/property/variable-response boundaries; unresolved operation-row count remains 13. No live BMC request was sent.
- Follow-up CM Provision response analysis closes children `0x86`/`0x87` wire encoding: `getOTPKey` (required operand A, no B) and `getOTPSerNum` (no operands) return the exact D-Bus string byte range as response bytes, without an appended NUL. Provider helper assembly confirms `end - begin` allocation and memcpy. Added exact route metadata and a focused regression; regenerated both docs. Focused tests: 19 passed; generator freshness, doc sync (2,409 tests), and whitespace checks pass. Parent remains Partial for other backend semantics; no live BMC request was sent.
- Current contract recount: 12 primary operation rows still have `semantic_unresolved_reason` set (not 13 as the earlier handoff stated); the exact list is recoverable from `primary.operations` in the contract JSON.
- Follow-up MMBI static analysis found the exact target `/usr/libexec/mmbibridged` in the pinned rootfs (SHA-256 `d95553c4d12415fca43e5ec933218046775a881b030988d4d899900a4478d6d3`, build ID `f65b6c94a47b868d882ffb5f8ff62537cfca3663`). The pinned `.data.rel.ro` table ties `setEncHashData` (`ay -> n`, callback `0xf270`), `checkEncHashData` (`() -> n`, `0xd124`), and `getEncHashData` (`() -> n, ay`, `0xd418`) to exact daemon handlers. Provider callsites map SET/GET to the first and third methods; `checkEncHashData` has no IPMI callsite. Documented status mapping and the 8-byte GET gate in zipmi and both generated docs. Exact inner key-byte transforms remain under analysis. Focused X14 tests (18), generator freshness, doc sync (2,408 tests), and whitespace checks pass. Current local contract SHA-256: `f25e4bedd0fda96fdfb712ef070800b26321c2fa4a37e0f1b4ee9f5861a5c3c7`. No live BMC request was sent.
- `ClearConfigOption` now resolves its indirect call to `OEMSESCommand` at mapped VA `0x000a84cc` (ELF VA `0x000984cc`): the helper removes selected entries from a configured directory and an additional fixed path, sends a system-bus request, and emits MEL event `0x7b` only when called with a nonzero third argument. The `0x00000004` mask passes 1; `0x02000000` passes 0. Exact configured paths/patterns, D-Bus endpoint/method, and higher-level option labels remain unresolved. Updated both generated docs and added a contract regression assertion; no live BMC request was sent.
- `OEMAddDelUser` now also documents the target's empty-slot-only create / populated-slot-only delete gates (`0xCC` otherwise), first-ASCII-`G` credential split, and exact user-delete D-Bus service/path/interface/method. Updated the compact row and the focused test that still incorrectly expected this behavior to be unresolved. Focused X14 tests: 19 passed; no live BMC request was sent.
- Review (2026-09-30): resolved CM Provision child `0x08`'s provider call, required two-byte operand staging, u16be success response, and `0xd6` negative-call mapping. The exact pinned `smci-provision-mgr` exports `getUFMAntiRBID (q -> i)` but not provider-targeted `getAntiRBID`; document this as a static provider/daemon incompatibility prediction (including the unproven signature compatibility), not a live-observed failure. Focused X14 tests, generated-doc freshness, and doc sync pass; no live BMC request was sent.
- Follow-up CM Provision child `0x06`: mapped its required operands, no-argument exception (`a=0,b=3`), transformed D-Bus arguments, string parsing branches (four packed-BCD bytes for `a=0`, three parsed bytes for `a=2`, otherwise raw bytes), and `0xd6` call/result error. The exact pinned daemon has inventory strings but no public `getFWInventory` vtable callback, so documented the likely static backend mismatch without claiming live behavior. Added exact endpoint/method metadata for children `0x06` and `0x08`; 19 focused tests, generator freshness, doc sync (2,409 tests), and `git diff --check` pass.
- Follow-up CM Provision children `0x84`/`0x85` now include exact no-argument D-Bus signatures, ignored-operand behavior, raw boolean response, and the exported daemon methods. Child `0xDB` now documents absent/non-5 selector behavior, operand-B ignore, exactly 256-byte truncate/zero-pad behavior, and explicitly unresolved pathname. Both X14 docs regenerated; 19 focused tests, generator freshness, doc sync (2,409 tests), and `git diff --check` pass.
- CM Provision children `0x05` and `0x20` now document the exact target validation/mapping. Rechecking the `0x05` branch corrected an independent audit's mistaken claim: A>=2 is rejected, while A=0/1 accepts B<=2; the existing CLI validator already matches. `0x20`'s selector-specific u16-to-u8 normalization and the target's expected D-Bus signatures are documented, preserving the caveat that stripped daemon callbacks do not prove return types. Added a guard regression; 20 focused tests, generated-doc freshness, doc sync (2,410 tests), and `git diff --check` pass.
- Corrected CM Provision child `0x07`: it is a lockout-gated CPLD feature-bit read, not an indexed task-status query. The provider's first `getBmcConsoleLockout` call sends `a+4` despite the pinned daemon's no-argument export (static InvalidArgs prediction); the later `readCPLDFeatbit` backend signature remains unverified. Updated command name, route metadata, evidence and CLI regression. Focused X14 tests: 20 passed; generator freshness, doc sync (2,410 tests), and whitespace checks pass.
- CM Provision children `0x02` and `0x09` now record the exact exported no-argument task-status query/u32-to-u8 truncation and the `get_rot_cpld_reg` → SecurityManager `readCpldReg` path (arbitrary required selector, signed-int32-to-low-byte result); the SecurityManager implementation remains unavailable. Added route metadata and tests; both generated docs remain current and all focused/doc-sync/whitespace checks pass.
- Review (2026-09-30): corrected CM Provision child `0x20` from an overstated accepted selector set and u16 interpretation: `4`, `6`, `7`, and values above `9` reject; the daemon exports a boolean return, mapped to `0x02`/`0x00` except selector `8`, which passes the raw boolean. Child `0x21` also maps boolean true/false to `0x02`/`0x00`; the daemon can report true even on an erase-failure log path. Added exact local-helper D-Boot behavior for child `0x0f`, including its separate CpldUpdateMgrSvc/CpldDevice path, and detailed CMOS/AC-cycle child `0x54`/`0x55` side effects and response-on-failure behavior. Focused X14 tests and generated docs updated; no live BMC request was sent.
- Review (2026-09-30): recovered IPv6 query response encodings from the provider plus the pinned `libsmci.so.0.0.1` (SHA-256 `3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf`): mode query returns normalized mode + SLAAC bytes; selector 2 returns concatenated IPv6 address/prefix records; DUID returns colon-separated hex pairs decoded to octets; default-gateway translation returns 16 packed bytes plus the helper's zero terminator. Added setter-length/query-selector validation to the zipmi CLI while leaving setter field bytes raw pending recovery. No live BMC request was sent.
- Follow-up IPv6 setter trace (2026-09-30): provider disassembly narrows operation 2's 16-byte data record: byte 0 is a 0..2 mode, bytes 1–2 are boolean-bounded, and byte 2 is passed as SLAAC status in mode 1 or selects IPv6 address deletion vs add/reconcile in mode 2. Read-only extraction restored the exact pinned `libsmci.so.0.0.1` (SHA-256 `3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf`); its `translateIpv6ToStr` helper calls `inet_ntop(AF_INET6)` without an explicit 16-byte vector-length check. The provider/helper vector-length flow is not fully reconciled, so any short-input concern remains conditional. Enforced proven mode/flag bounds in the named zipmi route, added regression cases, and updated both generated docs. Remaining setter fields/property mappings stay explicitly unresolved; no live BMC request was sent. Verification: 21 focused X14 tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass.
- Review (2026-09-30): corrected stale CM Provision evidence after extracting the exact X14 rootfs. `smci-security-mgr` is present (SHA-256 `4c416258c84653cfe739bafc8d3e0a5ed38977dc4b5787621672524da6e3f4f7`, Build ID `a4823d9403960d8d495a166783b40b683973fb07`); its `readCPLDFeatbit()` is no-argument `int64`, implemented with `/dev/spitee` and ioctl `0xC0026B11`. Child `0x07` passes an argument and expects signed int32; the prior `getBmcConsoleLockout(u8)` call also mismatches its pinned no-argument daemon export, so the second call is not expected to be reached on this image pair (static, not live-tested). Child `0x09`'s callback is present, though its full backend effects remain unrecovered. Updated contract, CLI purpose, both generated docs, and regression assertions. Verification: 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass; no live BMC request was sent.
- Follow-up CM Provision child `0x09`: pinned image scripts corroborate register 0 bit 4 as MSMI-latching enable, register 1 bit 2 as temporary surprise-reset control, and register 8 bits 6/7 as BMC-reset/factory-default flags. Added source hashes and the explicit limitation that these examples are not the full CPLD register map and do not recover the SecurityManager callback's complete hardware/error behavior. Refreshed both docs; 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass. No live request sent.
- Review (2026-09-30): corrected `OEMGetPSUInfo`'s stale claim that its backend was absent. The pinned rootfs includes `/usr/bin/smci-pws` (SHA-256 `2453900f9b112ee1ee55576e081cc1074df0d6efd5d263ad8011bbbb580487ce`, Build ID `dcda7666af6c16969b1e19757630b12c867951f8`), launched as `com.SMCI.PWS`; its string/vtable inventory contains `com.smci.psu.info.GetPSURaw` and a two-byte unsigned-char callback shape. The callback failure path is refined in the follow-up below; command-byte semantics and backend result/error behavior remain unresolved. Updated contract and both docs; 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass. No live BMC request was sent.
- Follow-up PSU callback trace: corrected the characterization of `Can't get PSURaw Data after retries.` from a log string to the actual static failure path: the matching two-byte callback adapter constructs `std::logic_error` with this text and throws via `__cxa_throw` at code address `0x00044ac8`. Retry count, command decoding, backend reads, and D-Bus/IPMI failure mapping remain unresolved. Updated contract, both generated docs, and regression assertions; 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass. No live BMC request was sent.
- Review (2026-09-30): traced the pinned `smci-pws` callback `FUN_00054818` into raw helper `FUN_0005f494`. `GetPSURaw(command,length)` sends the command byte and optional read to `/dev/i2c-%d` via ioctl `0x707`; expected ioctl result is 1 (command only) or 2 (command plus read). The helper allows four ioctl attempts, with 100 ms sleeps between mismatches; the callback allows ten helper attempts with 100 ms sleeps, then throws `std::logic_error("Can't get PSURaw Data after retries.")`. Returned bytes are appended as a D-Bus byte array. Corrected the PSU contract and regenerated both docs; only the provider's D-Bus/IPMI failure-to-completion-code mapping remains unresolved. No live BMC request was sent.
- PSU provider follow-up: `FUN_000c7298` throws `sdbusplus::exception::SdBusError` on a negative `sd_bus_call`; the shared array-reply decoder `FUN_000d22fc` throws the same type on malformed reply operations. `OEMGetPSUInfo` has no local catch/CC translation around the call, so only the outer IPMI framework's exception mapping remains unknown. Added provider error evidence and regression assertions; no live BMC request was sent.
- Review (2026-09-30): corrected CM Provision child `0x20` from an overstated accepted selector set and u16 interpretation: `4`, `6`, `7`, and values above `9` reject; the daemon exports a boolean return, mapped to `0x02`/`0x00` except selector `8`, which passes the raw boolean. Child `0x21` also maps boolean true/false to `0x02`/`0x00`; the daemon can report true even on an erase-failure log path. Added exact local-helper D-Boot behavior for `0x0f`, including its separate CpldUpdateMgrSvc/CpldDevice path, and detailed CMOS/AC-cycle child `0x54`/`0x55` side effects and response-on-failure behavior. Focused X14 tests and generated docs updated; no live BMC request was sent.
- Review (2026-09-30): closed the MMBI selector `0x20` inner-byte and result semantics against the pinned `mmbibridged`: byte 0 selects the channel-dependent Blowfish schedule, remaining bytes are raw candidate key material, and SET validates encryption/decryption of the repeated little-endian 8-byte BoardId block before storing it as GET data. Corrected `9CBlowfish` to its actual RTTI meaning (class metadata, not a key) and removed MMBI from the unresolved semantic-row count; `checkEncHashData` is exported but has no IPMI provider callsite. Both generated docs updated. Verification: 21 focused tests, generated-doc freshness, doc sync (2,411 tests), and `git diff --check` pass; no live BMC request was sent.
- Review (2026-09-30): corrected `ClearConfigOption` helper attribution: mapped VA `0xa84cc`/ELF VA `0x984cc` is a separate anonymous cleanup function, not `OEMSESCommand`. Its pinned disassembly resolves the directory `/usr/share/log`, fixed path `/usr/share/log/rsyslog_server`, and `org.freedesktop.systemd1.Manager.ReloadUnit("rsyslog.service", "replace")`; exact directory-entry selection and higher-level mask names remain unknown. Regenerated both docs; 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass. No live BMC request was sent.
- Review (2026-09-30): closed `OEMGetSetBBP`'s remaining semantic note from the complete handler body: operation 1 reads only `SystemLockdownEnable` and applies bounds/payload checks; operations 0/3 only validate; no branch reads/writes BBP state. Since `parameter_id` and `value_selector` are used only as opaque range-checked compatibility bytes and the target defines no enum, their semantic labels are explicitly not invented. Both docs regenerated. Verification: 21 focused tests, generated-doc freshness, doc sync (2,411 tests), `git diff --check`; primary unresolved semantic rows: 10. No live BMC request was sent.
- Review (2026-09-30): closed `GetBRCMHDDBitmap` at target-observed semantics: bitmap 2 is set exactly when the per-drive `FwState` property equals numeric 1. Removed the unverified `UNCONFIGURED_BAD` label from target effects/field meaning; retained the upstream enum only as explicitly unverified supporting context. Both docs regenerated. Verification: 21 focused tests, generated-doc freshness, doc sync (2,411 tests), `git diff --check`; primary unresolved semantic rows: 9. No live BMC request was sent.
- Review (2026-09-30): traced CM Provision child `0x03` through pinned `libsmci.so.0.0.1` (function `get_rot_cpld_version`, ELF VA `0xccba8`, SHA-256 `3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf`) to SecurityManager `readCPLDVersion() -> int64`; the IPMI provider returns the low 24 bits as three low-to-high bytes without sign/status translation. The helper throws on D-Bus construction/call/reply-read failures, with no local child completion-code mapping. Added exact daemon method evidence and updated both docs; 21 focused tests, generator freshness, doc sync (2,411 tests), and `git diff --check` pass. Underlying daemon hardware-read behavior and outer exception mapping remain explicit gaps; no live request sent.
- Review (2026-09-30): recovered `LicenseFileAction` MEL mapping from the target's KCS/RMCP branches: operation 1 with slot 1 emits EventId 5 for `SFT-OOB-LIC`, slot 2 for `SFT-DCMS-SINGLE`, both with status `deactivated`; other slots skip those branches. Kept the numeric license mask bits unresolved because the pinned `libsmci` hook names no product feature. Added branch-map regression assertions and regenerated both docs; no live BMC request sent.
- Review (2026-09-30): checked `OEMSetGetLinkConf`'s fixed `0x59` mask against the official X14/H14 BMC manual. The manual confirms the UI choices (auto, 100M half/full duplex, 1G full duplex), but neither it nor the pinned provider maps the choices to individual mask bits; kept that mapping unresolved and documented the cross-artifact evidence in both pages.
- Review (2026-09-30): decompiled the anonymous `ClearConfigOption` helper at ELF VA `0x984cc` with the existing X14 Ghidra project. Recovered its `/usr/share/log` byte-prefix filter, staging of matches, and per-path `std::filesystem::remove`; the filter string object resides in BSS at ELF VA `0x1ed9e0`, but its runtime-initialized value is not file-backed. Updated both docs and regression assertions; selector match names and higher-level option labels remain unresolved. No live BMC request sent.
- Review (2026-09-30): traced pinned `smci-security-mgr`'s `readCPLDVersion()` ioctl path: `/dev/spitee`, request `0xc0206b0c`; on open/ioctl error, an uninitialized stack-buffer word is copied into the returned int64 low word, then CM Provision child `0x03` exposes its low 24 bits. The child can therefore disclose three stack bytes on that failure path; retained this as conditional static evidence (not live-confirmed), preserved the outer dispatcher unsafe gate, updated both docs and regression checks. The outer framework's D-Bus-exception mapping remains unknown; no live request sent.
- Review (2026-09-30): expanded CM Provision child `0x09`'s shipped-image register-use evidence from registers 0/1/8 to also cover the BoardId-7504 fan-delay write at 0x0a, the boot-time clear at 0x0b, and the separately accessed 0x18 boot-status bits. Marked the raw `/dev/spi1nand0` path as distinct from the D-Bus read path; bit-level meanings and callback error behavior remain open. Regenerated both docs and added hash-backed assertions; no live probe.
- Review (2026-09-30): recovered the matching `smci-security-mgr` low-level CPLD reader at ELF VA `0x5c8f4`: open `/dev/spitee` O_RDWR, place `(register & 0xff) << 16` in a zeroed u32, ioctl `0xc0046b01`, copy the low byte on success, and return `-5` on open/ioctl failure. Its D-Bus callback linkage/result mapping is still not directly established from the stripped image. Added contract and both-doc summaries plus regression assertions; 21 focused tests and generator/doc-sync gates pass; no live request sent.
- Review (2026-09-30): resolved CM Provision child `0xdb`'s pathname from the same provider PC-relative pointer passed to `access()` and `read_binary_file()`: `/usr/share/log/3068db.log` (callsite `0xee754`, rodata `0x1b1970`). Contract, CLI operation detail, and both generated pages now document the `a=5` gate and exact 256-byte truncation/zero-padding behavior. Static evidence only; no live BMC request.
- Review (2026-09-30): recovered CM Provision child `0x0f`'s `dumpDboot(B,0)` device map from the provider switch and path construction: B=0 Backplane_0_CPLD_0; B=3 AOMboard_1_CPLD_1; B=5 MidplaneSBB_CPLD_1; B=9 Fanboard_1_CPLD_1. The pinned matching service identifies its `CpldDevice`/MachXO2 dump implementation and `/tmp/cpld_flash_dump.bin`, while full dump data/error semantics remain unproven. Zipmi now validates B against the four accepted selectors for dump mode and preserves ignored B in status-query mode; contract and both docs updated. No live request.
- Follow-up D-Boot daemon trace: the pinned `smci-cpld-update-mgr-svc` MachXO2 implementation at ELF VA `0x2d908` reads the D-Boot JEDEC ID, opens `/tmp/cpld_flash_dump.bin` with `O_WRONLY|O_CREAT|O_TRUNC`/0666, and reads/writes three 64-KiB blocks starting at `0x0fff0`, `0x1fff0`, and `0x2fff0` (0x30000-byte complete output). Failed operations can leave a partial file; provider-side D-Bus exception/completion handling remains unresolved. Contract and both docs updated; no live request.
- Review (2026-09-30): resolved CM Provision child 0x21's BIOS-staging Properties.Set value from the pinned smci-provision-mgr (SHA-256 bc25b26a97a6400770c0d844a08785e8ab50d5f9f7d9ddf549c50eaf845df8cf): the string variant is ne_implINS2_10bad_alloc_EEEEE, copied from the C string at ELF VA 0x4bba4 and passed from the local std::string to append at 0x21138. This is a suffix of a Boost RTTI name; recorded as observed behavior without assigning intended semantics. Updated contract, CLI purpose, both generated docs, and regression assertion. Focused X14 tests: 22 passed; generator freshness, doc sync (2,412 tests), JSON parse, and git diff --check pass. The unresolved parent row count remains 9 because other CM Provision children and separate operations remain unresolved. No live BMC request sent.
- Review (2026-09-30): recovered the exact operation-1 IPv6 setter lockdown gate from provider PC-relative strings and its optimized body: `xyz.openbmc_project.Settings:/com/SMCI/SysLockdown`, `com.SMCI.Managers.Item.SysLockdown.SysLockdownEnable`; true returns `0xD4` before applying that setter. Added pinned addresses/evidence and a regression assertion, removed a duplicate JSON `resolved_setter_prefix` key that obscured which detail survived parsing, and regenerated both X14 docs. Focused tests, generator freshness, doc sync, JSON parsing, and whitespace checks pass. IPv6 setter fields and property mapping remain unresolved; no live BMC request sent.
- Review (2026-09-30): verified the latest IPv6 operation-2 DHCP property evidence, regenerated both X14 pages, and reran focused tests (22 passed), generated-doc freshness, doc sync (2,412 tests), JSON parsing, and `git diff --check`; all pass. The latest attempt initially found stale generated pages, now corrected. Primary semantic unresolved row count remains 9; no live BMC request sent.
- Review (2026-09-30): traced IPv6 operation-2 mode normalization and invalid-data gate in the pinned provider: mode 0 maps to DHCPv6 mode 2/SLAAC true; mode 1 maps to mode 3/SLAAC false; mode 2 requires data byte 1 = 0 or returns 0xCC, then uses data byte 2 for delete-vs-add/reconcile. The DNSEnabledv6 false setter condition is now exact (getter false and normalized mode 2). Tightened zipmi's CLI validator, both generated docs, and regressions. Focused tests: 22 passed; generator freshness, doc sync (2,412 tests), JSON parsing, and `git diff --check` pass. No live BMC request sent.

## 2026-09-30 — Complete Supermicro X14 semantic closure

- [x] Resolve `ClearConfigOption`'s runtime filename prefix and exact cleanup behavior.
- [x] Close Broadcom compact logical-drive PRL/RLQ/SRL mappings against SNIA DDF.
- [x] Close link-capability and license-product bit mappings from pinned callsites and UI artifacts.
- [x] Recover IPv6 operation 1's complete 20-byte setter layout and operation 2's malformed 16-byte path.
- [x] Close every CM Provision child boundary, pinned-daemon match/mismatch, response encoding, and side effect.
- [x] Regenerate both X14 HTML views and prove catalog, generator, focused, and full-suite consistency.

### Review

- Primary X14 `semantic_unresolved_reason` count is zero across registrations and operations.
- IPv6 operation 1 is the defined setter: mode, SLAAC flag, action flag, 16 address bytes, and prefix. Operation 2 accepts 16 bytes but reuses the 20-byte consumer, causing three uninitialized `inet_ntop` bytes plus out-of-bounds vector scan/prefix reads; zipmi documents the target defect and preserves the exact accepted boundary.
- CM Provision child `0x86` returns fixed ASCII `111111111` on its pinned-daemon success path; mismatched children `0x06`–`0x08` remain documented as exact static incompatibilities rather than claimed successes.
- `ClearConfigOption` deletes `/usr/share/log/mel*`, removes `rsyslog_server`, reloads rsyslog, and gates MEL event `0x7b` by mask. No mutating live BMC request was sent.
- Accepted ClearConfig masks with no branch action intentionally remain unlabeled: their exact success/no-op behavior is closed, while the pinned target supplies no honest subsystem name to document.
- Proof: X14 generator `--check`, JSON parse, `git diff --check`, and 22 focused tests pass; full suite passes 2,412 tests with two pre-existing Scapy deprecation warnings.

## 2026-10-01 — X14 external-input safety review

### Review

- The exact X14 network and host IPMI binaries use length-aware RMCP/session parsing, typed request decoding, privilege checks, exception translation, PIE, NX, full RELRO, stack protectors, and glibc fortified calls; these are mitigations, not an end-to-end memory-safety guarantee.
- `OEMGetSetBootOrderInstance` has no direct wire-triggerable buffer overflow in its leaf: its write copy is capped at eight bytes. It nevertheless accepts surprising optional/truncating layouts, reads its fixed file without a size cap, follows symlinks, and writes non-atomically while reporting some persistence failures as success.
- The provider catalog already proves end-to-end counterexamples: `OEMGetSetNVMeSSDParameters` selector `0x6c` permits authenticated out-of-bounds paging beyond a 215-byte vector, and `ReadMemoryCmd` can copy past its single-page mapping near a page boundary. Typed decoding protects request shape but cannot repair unsafe leaf arithmetic.
- At that static-review checkpoint, no malformed live requests had been sent. Recommended next proof was snapshot-backed boundary fuzzing of netipmid, D-Bus dispatch, and each raw OEM leaf under sanitizers where source builds are available.
- `UploadOOBData` (`30/a0/0c`) plus the existing download protocol forms a statically complete Administrator physical-memory exfiltration chain: file type 3 runs `mem -f /var/oob/bios_fullsmbios -r 0xbff00000 -c <u32 count>`, download type 7 copies that exact path into the reservation staging file, and `FileDownload` returns it in chunks of at most 1500 bytes. The bundled `mem` utility maps the requested count and writes it verbatim; `0x100000` bytes reaches the end of the AST2600's 1-GiB SDRAM window from the fixed start address. Larger counts are unbounded by the handler and may fault or exhaust storage.
- Confirmed provider bugs: `30/70/6c` can disclose up to 255 bytes beyond its 215-byte NVMe record; `30/70/90` with an empty/short remainder, `30/74` with an empty request, and `30/70/bc 0a` with an empty remainder perform unchecked reads and are likely daemon-crash paths. No remotely controlled OOB write was established.
- Additional attack surfaces retained for lab testing: fixed-path upload integer wrap/resource exhaustion and conditional local symlink write, virtual-media SSRF/credential forwarding, IPv6 setter OOB/uninitialized reads, fixed-path decompressor/parser exposure, and raw I2C writes. No direct remote shell-command injection, remote path traversal, or provider-only RCE was proved.
- Checkpoint proof: 34 focused X10/X14 tests and the full 2,424-test suite pass; generated references, JSON parsing, documentation sync, and `git diff --check` pass. After the shared registry was repaired, artifact lookup verified the new live-evidence record. The broader sweep runs again and reports 34 current artifacts plus seven unrelated silent-drift records and pre-existing duplicate/orphan findings.

## 2026-10-02 — Optional Set User Password prompt

- [x] Preserve `zipmi user set password USER_ID PASSWORD [16|20]` for scripts.
- [x] Allow `zipmi user set password USER_ID` and securely prompt twice without echoing the password.
- [x] Reject mismatched confirmation before opening a session or sending a packet.

### Review

- The parser now makes only the existing password positional optional; explicit-password packet framing is unchanged.
- Prompted and explicit passwords share the existing UTF-8 byte-length validation and exact 16/20-byte Set User Password payload builder.
- Focused parser/effect verification passes 69 tests; the full suite passes 2,427 tests with two existing Scapy deprecation warnings. X14 static inspection confirms its `chpasswd` PAM service includes `common-password`, which updates both `/etc/shadow` and encrypted `/etc/ipmi_pass` through `pam_unix.so` and `pam_ipmisave.so`; direct credential-file editing is unnecessary.
- The iDRAC10 Set User Password reference now retains the X14 comparison without attributing it to Dell: X14's shipped validator requires 8–20 characters, at least three of four character classes, no boundary spaces, and a password distinct from the username and its reverse. A four-class 13-byte password succeeded live in the 16-byte slot; a policy rejection returned misleading `0xC8`. The note distinguishes IPMI field width from vendor password policy.

## 2026-10-02 — ipmitool-compatible channel setaccess

- [x] Add `channel setaccess CHANNEL USER_ID key=value...` for Set User Access `0x06/0x43`.
- [x] Preserve unspecified access flags by reading the current `0x44` record first.
- [x] Keep the existing `channel set-access` command bound to distinct Set Channel Access `0x06/0x40` semantics.
- [x] Document and regression-test the ipmitool-compatible spelling and payload.
- [x] Auto-negotiate the highest accepted ADMIN/OPERATOR/USER session privilege when `--max-priv` is omitted.
- [x] Keep explicit `--max-priv` requests strict for reduced-privilege security testing.

### Review

- X14 live evidence established that user 8 was enabled but initially had link authentication and IPMI messaging disabled with NO ACCESS. Local `ipmitool` accepted USER and ADMIN but rejected CALLBACK with `0xCC`; after USER access was set, the record reported both LAN flags enabled.
- The new command accepts `callin`, `ipmi`, and `link` as `on|off`, plus named or numeric IPMI privilege levels. It validates every assignment before opening a session, reads the current record once, preserves omitted fields, and sends one Set User Access request.
- `user list` now decodes raw `0x44`/`0x46` responses and validates their lengths, so a completion-only success response is reported as a protocol error instead of escaping as Scapy's `AttributeError: max_user_count`.
- Live source-tree proof passed: `channel setaccess 1 8 ipmi=on link=on callin=on privilege=2` returned success and remote readback reported USER with both LAN flags enabled. The `eight` account authenticated with `--max-priv user` and completed `channel info 1`; its `user list` request was correctly denied by the BMC with `0xD4` and zipmi returned a bounded error without a traceback.
- Default privilege negotiation reuses the authenticated session and falls back only on Set Session Privilege completion code `0x81`; it does not issue extra RAKP logins or depend on ADMIN-only Get User Access. Live X14 proof with `eight` showed ADMIN → OPERATOR → USER and completed `channel info 1`, while explicit `--max-priv admin` still failed with `0x81`.
- Verification passes all 2,444 tests with two existing Scapy deprecation warnings.
