# OEM handler-mirror survey — cross-vendor

As the BMC firmware corpus grows, every stack gets checked against every other for **mirrored handler functions** — shared symbols expose shared code lineage (who really wrote whose BMC), and shared *normalized* names expose the common IPMI spec surface. This is a standing comparison; re-run it whenever a new vendor is cataloged.

## Corpora

| Stack | Family | Symbol source | Handlers |
|-------|--------|---------------|----------|
| ASMB-787 | AMI MegaRAC | binary RE (`g_*_CmdHndlr` tables) | 353 |
| MegaRAC-ref | AMI MegaRAC | curated AMI handler groups (`oem/megarac.py`) | 222 |
| iDRAC9 | Dell / Avocent | binary names (`oem/idrac9_binary_names.py`) | 167 |
| iDRAC6 | Dell / Avocent | binary names (`oem/dell_binary_names.py`) | 163 |
| Supermicro | (smcipmi RE) | tool-derived names (`oem/supermicro_known_context.py`) | 106 |

## Exact handler-symbol overlap — code lineage

| ∩ | ASMB787 | MegaRAC-ref | iDRAC9 | iDRAC6 | Supermicro |
|---|--------:|------------:|-------:|-------:|-----------:|
| **ASMB787**    | — | **78** | 0 | 0 | 1 |
| **MegaRAC-ref**|   | — | 0 | 0 | 0 |
| **iDRAC9**     |   |   | — | **123** | 2 |
| **iDRAC6**     |   |   |   | — | 2 |
| **Supermicro** |   |   |   |   | — |

Two dense clusters, **disjoint from each other**:

- **AMI MegaRAC** — ASMB-787 ↔ MegaRAC-ref share **78 identical symbols**. The Advantech board is running stock AMI OEM handlers.
- **Dell / Avocent** — iDRAC9 ↔ iDRAC6 share **123 identical symbols** (`CmdChassisControl`, the `CmdOEMMASER*` / `CmdOEMVflash*` families …), six years apart. Same source tree.
- **AMI ∩ Dell = 0** in both directions. Independent codebases. The Dell example that kicked this off bears out: iDRAC is *not* an AMI stack.

## The 78 shared AMI handlers (ASMB-787 ≡ MegaRAC-ref)

Every AMI OEM feature the ASMB-787 exposes is stock MegaRAC — including the security-relevant ones:

```
AMIAccessRedisDB  AMIActiveSessionClose  AMIAddExtendSelEntries  AMIControlDebugMsg
AMIGETExtendSelData  AMIGeneratePassword  AMIGetADConf  AMIGetAllActiveSessions
AMIGetAllPreserveConfStatus  AMIGetBackupFlag  AMIGetBiosCode  AMIGetBiosCommand  AMIGetBiosFlag
AMIGetBiosResponse  AMIGetDebugMsgStatus  AMIGetExtendedPrivilege  AMIGetFWCfg  AMIGetFWProtocol
AMIGetFirewall  AMIGetHostAutoLockStatus  AMIGetHostLockFeatureStatus  AMIGetLDAPConf
AMIGetMediaInfo  AMIGetNTPCfg  AMIGetPamOrder  AMIGetPreserveConfStatus  AMIGetRAIDInfo
AMIGetRISConf  AMIGetRMediaCfg  AMIGetRadiusConf  AMIGetRedirectedMediaInfo  AMIGetRemoteKVMCfg
AMIGetRunTimeSinglePortStatus  AMIGetSNMPConf  AMIGetServiceConf  AMIGetTftpProgressStatus
AMIGetTimeZone  AMIGetUBootMemtestStatus  AMIGetVmediaCfg  AMIManageBMCConfig
AMIMediaRedirectionStartStop  AMIPLDMBIOSMsg  AMIPartialAddExtendSelEntries
AMIPartialGetExtendSelEntries  AMIRESTinterface  AMIRISStartStop  AMISendToBios
AMISensorThresholdAcrossResets  AMISetADConf  AMISetAllPreserveConfStatus  AMISetBackupFlag
AMISetBiosFlag  AMISetBiosResponse  AMISetExtendedPrivilege  AMISetFWCfg  AMISetFWProtocol
AMISetFirewall  AMISetHostAutoLockStatus  AMISetHostLockFeatureStatus  AMISetLDAPConf
AMISetMediaInfo  AMISetNTPCfg  AMISetPamOrder  AMISetPreserveConfStatus  AMISetPwdEncryptionKey
AMISetRISConf  AMISetRMediaCfg  AMISetRadiusConf  AMISetRemoteKVMCfg  AMISetRunTimeSinglePortStatus
AMISetSNMPConf  AMISetServiceConf  AMISetTimeZone  AMISetUBootMemtest  AMISetVmediaCfg
AMIStartTFTPFwUpdate  AMIVirtualDeviceGetStatus  AMIVirtualDeviceSetStatus
```

Security-relevant subset: `AMIAccessRedisDB`, `AMIActiveSessionClose`, `AMIControlDebugMsg`, `AMIGeneratePassword`, `AMIGetAllActiveSessions`, `AMIGetAllPreserveConfStatus`, `AMIGetBackupFlag`, `AMIGetDebugMsgStatus`, `AMIGetExtendedPrivilege`, `AMIGetFirewall`, `AMIGetHostAutoLockStatus`, `AMIGetHostLockFeatureStatus`, `AMIGetPreserveConfStatus`, `AMIManageBMCConfig`, `AMISetAllPreserveConfStatus`, `AMISetBackupFlag`, `AMISetExtendedPrivilege`, `AMISetFirewall`, `AMISetHostAutoLockStatus`, `AMISetHostLockFeatureStatus`, `AMISetPreserveConfStatus`, `AMISetPwdEncryptionKey`.

**Implication for the `raw 0x32 0x66` restore-defaults backdoor:** the `g_AMI` OEM table is stock AMI, not an Advantech addition — so the no-privilege restore-defaults / root-password / Redis-access handlers are expected to be **AMI-wide**, present on any MegaRAC SP-X board (Supermicro, Tyan, Gigabyte, Lenovo, ASUS/ASMB, whitebox), not unique to this one.

## Normalized (function-level) overlap — spec surface

Prefixes stripped (`Cmd`/`AMI`/`Dell`/`Get`/`Set`) and cased down:

| Pair | Functions | What they are |
|------|----------:|---------------|
| ASMB787 ∩ MegaRAC-ref | 54 | AMI OEM + shared std |
| ASMB787 ∩ iDRAC9 | 35 | **mandatory standard IPMI only** |
| ASMB787 ∩ iDRAC6 | 33 | mandatory standard IPMI only |
| iDRAC9 ∩ iDRAC6 | 105 | Dell std + OEM |
| any ∩ Supermicro | 1–3 | see caveat |

AMI↔Dell normalized matches are **all** IPMI-2.0-mandatory commands (ChassisControl, ColdReset, GetSELInfo, ReadFRUData, ReserveSEL, GetSystemGUID …) — shared because the *spec* forces them, with different symbol names on each side. No proprietary OEM handler crosses the AMI/Dell line.

## Caveat — Supermicro not yet placeable

Supermicro is widely believed to be AMI-based, but its corpus here comes from `smcipmi`/SMCIPMITool tool RE, which uses **ad-hoc command names** (`ResetBMCWatchdog`, `MasterWriteReadPMBus`), not the firmware's real handler symbols — so it shares only `GetSystemGUID` with AMI and `CmdReserveSEL` with Dell (coincidental naming). Placing Supermicro in a family needs its **real firmware symbols**. Pulling a Supermicro/Tyan/Gigabyte AMI image and re-running this survey is the open task — and the direct test of whether the restore-defaults backdoor is truly AMI-wide.

## Reproduce

```
# handler corpora: oem/{megarac,idrac9_binary_names,dell_binary_names,supermicro_known_context}.py
#                 + the ASMB-787 g_*_CmdHndlr extraction (scratchpad/cmdtables.json)
# exact overlap = code lineage; normalized overlap = spec surface
```
