# BCM5709 NCSI OEM Command Map (T710 / iDRAC6 sideband path)

**Target:** Dell PowerEdge T710, iDRAC6 1.70 (Nuvoton WPCM450 ARM/OABI, kernel 2.6.23.1),
Broadcom NetXtreme II BCM5709C (PCI 14e4:1639, 4-port LOM, bnx2 driver).

**MCP firmware on the BCM5709's management coprocessor:** `NCSI 2.0.11`
(string at `MCP_SCRATCH+0x30`, confirmed live on T710 via PCIe BAR0 indirect read —
see `~/phd/mobo/NIC/bcm5709/PoC-host-DMA-from-NIC.md`).

**Broadcom IANA PEN:** **4413 = 0x0000_113D**
(Linux `include/net/ncsi.h` → `NCSI_OEM_MFR_BCM_ID = 0x113d`). The b57udiag PDF
does **not** contain the IANA value — it only references PCI vendor `0x14e4` as
"manufacturing ID". OEM commands use NCSI cmd `0x50` with the 4-byte big-endian
manufacturer ID `00 00 11 3D` as the first payload bytes.

---

## Threat model

A compromised iDRAC6 has a working raw NC-SI control plane on its WPCM450 EMC
to **one** Broadcom BCM5709 NCSI package (the dedicated NIC, eth2/pkg-0) and
discovers — but cannot initialize — the second package that fronts the LOM
(eth3/pkg-1 — `Scan all package: The package id is 1 … NCSI: Second package
Exist!` but no `Enable Channel` ever sent). The BMC therefore has channel-0 NCSI
reachability today and a known-broken sideband to the LOM that newer iDRAC
versions (7/8/9) on the same silicon do drive successfully. Because the host
T710 has no IOMMU active (no DMAR ACPI table, no `intel_iommu=on`), **any
primitive that lets the BMC influence the BCM5709's DMA engines, BD-ring base
registers, MCP scratchpad, or MIPS firmware load is a direct path to arbitrary
host-physical write — no NIC firmware reflash required** if a register-write
sub-command exists, or a one-shot reflash via the standard NCSI fw-update flow
otherwise.

---

## DSP0222 mandatory commands (relevant ones only)

All command/response packets use EtherType `0x88F8`, dest MAC
`FF:FF:FF:FF:FF:FF`, channel ID = (PackageID<<5 | ChannelID). Command type
range 0x00-0x1A defined in DSP0222 v1.0.0; 0x1B-0x49 added in v1.2.0; 0x50 =
OEM escape. The BCM5709 ships `NCSI 2.0.11` MCP firmware which approximately
matches DSP0222 v1.0 era.

| Cmd | Name | Reaches DMA? | Notes |
|-----|------|--------------|-------|
| 0x00 | Clear Initial State | No | Standard handshake. iDRAC6 sends this for pkg-0 only. |
| 0x01 | Select Package | No | iDRAC6 sends. |
| 0x02 | Deselect Package | No | iDRAC6 sends. |
| 0x03 | Enable Channel | No | iDRAC6 sends for pkg-0; **never sent for pkg-1** on T710 1.70 (root cause of shared-NIC failure). |
| 0x04 | Disable Channel | No | |
| 0x05 | Reset Channel | No | Forces channel to Initial State. Combined with re-init it can stall/reroute host traffic but no DMA. |
| 0x06/0x07 | Enable/Disable Channel Network TX | No | Controls whether BMC can transmit; default-on after Enable Channel. |
| 0x08 | AEN Enable | No | Configures async event notifications back to BMC. |
| 0x09 | Set Link | No | Forces speed/duplex; can drop host link as side effect. |
| 0x0A | Get Link Status | No | iDRAC6 polls this continuously every ~1.6s on pkg-1 (we captured 18 RESPONSE packets at 22:32 PDT). |
| 0x0B | Set VLAN Filter | No | Configures up to 8 VLAN-tag filters. |
| 0x0C/0x0D | Enable/Disable VLAN | No | |
| 0x0E | Set MAC Address | No | Programs up to 8 unicast/multicast MAC filters into the MCP. **Standard primitive for "intercept host MAC" attacks.** No host-DMA, but does steer wire traffic. |
| 0x10/0x11 | Enable/Disable Broadcast Filter | No | |
| 0x12/0x13 | Enable/Disable Global Multicast Filter | No | |
| 0x14 | Set NC-SI Flow Control | No | |
| 0x15 | Get Version ID | No | Returns 40-byte response: NCSI ver, FW name (12 chars), FW ver (4 bytes), PCI DID/VID/SSID/SSVID, **Mfr ID (4 bytes)**. Used by `~/phd/bmc/dell/ncsi-probe-oabi.c` for fingerprinting. |
| 0x16 | Get Capabilities | No | Returns supported features bitmap and AEN control mask. |
| 0x17 | Get Parameters | No | |
| 0x18-0x1A | Get *Statistics | No | |
| 0x50 | OEM Command | **Possibly** | See next table. Per DSP0222 §6.4, OEM commands are exempt from the standard length checks. The 5709 NCSI 2.0.11 firmware's OEM dispatcher is the only spec-compliant escape to vendor extensions. |

**Reason codes** `0x0000` to `0x7FFF` are spec-defined; `0x8000-0xFFFF` are
OEM-defined. `0x0005 Invalid Payload Length` is returned by the i210 for a
wrong-size Set MNGONLY — same dispatcher pattern likely on the BCM5709.

---

## Broadcom OEM (via NCSI cmd 0x50 + Broadcom IANA 0x113D)

**Packet layout (after 14-byte Ethernet header, 8-byte NCSI header):**

```
  +0..+3   IANA Mfr ID (big-endian) = 00 00 11 3D
  +4       Broadcom sub-command ID (1 byte)
  +5       Sub-command parameter / index (1 byte, on most sub-cmds)
  +6..     Sub-command payload
```

This layout matches what the Linux kernel sends in
`ncsi_oem_gma_handler_bcm()` (kernel 6.16, `net/ncsi/ncsi-manage.c:720`),
where the only public Broadcom sub-cmd Linux uses is `0x01 Get MAC Address`.
**Everything below 0x01 and above 0x01 is undocumented in any public spec we
have on disk.** Most of what is "known" comes from the b57udiag tool's
host-side commands (which the diagnostic firmware exposes), and from
reverse-engineering of Broadcom's open-source-replacement work (meklort/
Ortega / Delugré).

| Sub-cmd | Name (b57diag analog) | Function | DMA/host-RAM relevance | Probe status (T710) | Source |
|---------|----------------------|----------|------------------------|---------------------|--------|
| **0x01** | Get MAC Address (GMA) | Retrieve permanent MAC for the requested channel | None — read-only L2 ident | Not probed yet on iDRAC6; trivially implementable via existing `ncsi_raw_send.c` | Linux `NCSI_OEM_BCM_CMD_GMA = 0x01`, payload length 12 |
| 0x02-0x07 | UNVERIFIED — gap | possibly Get Channel Info / Filter Get | Unknown | Not probed | No public source |
| 0x06? | UNVERIFIED — Get Filters | Read current MAC/VLAN/IP/Port mgmt filters back to BMC | Read-only — discloses filter state | Not probed; analogous to Intel cmd 0x03/0x06 | Inferred from `apeinfo -f` ("Show receive management filters") on b57diag — host-side equivalent exists on the silicon |
| 0x0E? | UNVERIFIED — Set Mgmt MAC | Program management filter MAC | None | Not probed; might overlap with DSP0222 0x0E | Inferred |
| 0x4F | UNVERIFIED — Vendor Sideband (OpenBMC variant) | Some Broadcom OEM commands have been observed on Mellanox-spec-style 0x4F; not confirmed for BCM5709 | Unknown | Not probed | DSP0222 v1.2 reserves cmd 0x4F, distinct from 0x50; mentioned in older OpenBMC patches |
| **(MTU-bounded data)** | UNVERIFIED — Firmware Image Update | Push firmware blob to MCP — standard for NCSI in-band fw update | **★★★ Reflash → full primitive** | Not probed; no public Broadcom NCSI firmware-update sub-cmd ID documented for BCM5709, but the silicon must support it because `b57udiag` `loadfw` and `loadbootcode` work, and Broadcom's UpdateXpress/iDRAC firmware-update package does push BCM5709 firmware in-band | b57udiag §10.47 loadfw, §10.52 loadbootcode (host-side equivalents). Sub-cmd ID for the NCSI variant is the load-bearing unknown. |
| **(register-window)** | UNVERIFIED — Indirect Register Read/Write | NCSI-tunneled equivalent of `BNX2_PCICFG_REG_WINDOW` indirect access | **★★★ Direct: BD-ring base, DMA_CONFIG, MAC mode — same write primitive as Path A in `PoC-host-DMA-from-NIC.md`** | Not probed; existence inferred from `apeinfo`'s ability to dump arbitrary register space, and from the fact that the b57diag tool's `inp`/`outp`/`mread`/`mwrite` interact with the device entirely over PCIe but logically the MCP can also be asked over NCSI. No public confirmation. | Inferred from b57udiag §10.193 inp, §10.194 outp, §10.95 mread, §10.94 mwrite — these are host-PCIe-side, but the underlying ability of the MCP to read/write arbitrary device registers (which is needed by `apeinfo -r`) means the OEM dispatcher *can* expose it; nobody has published the wire format. |

**Bottom line on the table above:** Of the Broadcom OEM sub-commands, only
**0x01 (GMA)** is publicly confirmed in mainline open source. The rest are
strong suspects but require live probing on the T710 (or recovery of
`libncsi.so.1` / `libncsiapp.so.1` from iDRAC9 — `bin/ncsiapptest` exists
under `~/phd/bmc/dell/dell-oem-analysis/idrac9-extract/squashfs-root/bin/` but
is stripped ARM EABI5 and references the libs only by name; the lib bodies
were not in the squashfs we extracted).

---

## Capabilities by category

### Direct host-RAM access primitives

| Capability | BMC-reachable? | Mechanism | Strength | Notes |
|-----------|----------------|-----------|----------|-------|
| **Hijack live BD ring (Path A)** | NO (host-only) | Map BAR0, splice descriptor with attacker `haddr_hi:haddr_lo`, ring doorbell | ★★★ | This is the Duflot/Delugré primitive. **Host-PCIe-side**, not BMC-side. b57udiag's `dmaw`/`dmar` are the documented diag-mode equivalents (see below). |
| **`dmaw -K <abs>` / `dmar -K <abs>`** (b57diag) | NO (host-only via diag fw) | The `-K` flag on §10.71 dmaw is documented verbatim as: *"DMA write to absolute address and hang the system (def=00000000)"*. §10.72 dmar `-K`: *"DMA read from absolute address"*. | ★★★ | The MCP silicon **does** expose an "arbitrary host phys address DMA" primitive; b57diag uses it. The unknowns: (a) is the same primitive callable over NCSI from the BMC, (b) does NCSI-2.0.11 MCP firmware on Dell-customized BCM5709 expose the dispatcher, (c) what is the OEM sub-cmd ID. This is the single highest-value question for the iDRAC6 attack path. |
| **`-K` proof of MCP DMA-arbitrary-host capability** | n/a — capability proof only | dmaw `-K=<HEX>` issues a DMA from NIC SRAM to an arbitrary host phys address chosen by the operator | ★★★ | b57udiag §10.71. Confirms the BCM5709 DMA engine accepts an unfenced 64-bit host phys target. Combined with the no-IOMMU situation on T710, this is the hardware property the attack rests on. |
| **Cold-bring-up unbound function (Path B)** | NO (host-only) | Unbind one of the 4 BCM5709 PCI functions, reset chip, build BD ring with `TARGET_PHYS_ADDR` | ★★★ | Documented in `~/phd/mobo/NIC/bcm5709/PoC-host-DMA-from-NIC.md`. Host-side only. |
| **NCSI-driven MCP register write → DMA setup** | UNVERIFIED — strongest BMC-only path | If a Broadcom OEM sub-cmd exposes register-window write, BMC programs `BNX2_DMA_CONFIG`, BD-ring base, and triggers TX/RX | ★★★★ | This is the goal of the research. The MCP runs `NCSI 2.0.11` which is **the same MCP that has full chip register visibility**. The MCP-to-chip register path is privileged. The question is whether the NCSI 2.0.11 OEM dispatcher offers an register-write doorway. Probe target #1. |
| **NCSI-driven MCP firmware update → patched MCP issues DMA** | UNVERIFIED — most likely BMC-only path | Push attacker MIPS/MCP firmware via standard NCSI in-band fw-update sub-cmd; new firmware issues DMA wherever it likes | ★★★★ | Reflash crosses the "no NIC firmware mod" constraint stated in the task. But: (a) `iDRAC6 1.70 NCSI init fails for pkg-1` means even reflash via shared-NIC path is blocked at pkg-1; pkg-0 reflash works. (b) `loadfw` semantics on the host-side equivalent in b57diag are well documented — load to TX/RX CPU; the NCSI variant must exist because Dell/Broadcom DUP-style fw updates traverse this path on iDRAC7+. Probe target #2. |
| **MAC filter "Set MAC" + receive-and-write-to-host descriptor pre-staging** | Partial (BMC-only) | Standard DSP0222 cmd 0x0E sets BMC's MAC filter; if BMC can additionally place an Rx BD that points at host phys, an incoming packet to that MAC is DMA-written into host RAM | n/a — no | This requires the Rx-BD-base register write, which is the same gap as the row above. Set MAC alone is insufficient. |

### Sideband filter manipulation (MNGONLY-equivalent, MDEF)

| Capability | BMC-reachable? | Mechanism | Notes |
|-----------|----------------|-----------|-------|
| Standard MAC filtering (NCSI 0x0E) | YES | Up to 8 filters, spec-defined | Works on T710 today for pkg-0 channel-0. |
| VLAN filtering (NCSI 0x0B–0x0D) | YES | Up to 8 VLAN tags | Spec-defined. |
| Broadcast filter (NCSI 0x10/0x11) | YES | | |
| Multicast filter (NCSI 0x12/0x13) | YES | | |
| **Equivalent of i210 `MNGONLY` (host-invisible exclusion)** | UNVERIFIED | The BCM5709 has `BNX2_RPM_MGMT_PKT_CTRL` (offset 0x180c), `BNX2_RPM_SORT_USER[0..3]` (offsets 0x1820-0x182c). These contain `MGMT_DISCARD_EN`, `MGMT_EN`, `MGMT_SORT`, `MGMT_RULE` bits that map onto the same "send to mgmt only" concept. Whether the NCSI 2.0.11 firmware exposes a sub-cmd to set these is unknown. | The Intel i210 trick from the X11SSZ research (`NCSI_OEM_MFR_INTEL_ID = 0x157`, Intel cmd 0x02 + param 0x0F Set MNGONLY) **does not work** on Broadcom — the IANA is wrong and the sub-cmd dispatcher is different. A Broadcom equivalent must exist (the RPM_MGMT registers are right there in the silicon) but the OEM cmd id is undocumented. |
| **Deep-packet ("flex") filter** | UNVERIFIED | No equivalent of the i210 Flex 128-byte TCO filter is documented in bnx2.h. The BCM5709 RPM has `MGMT_RULE`/`MGMT_SORT` rule slots; pattern depth is undocumented in the public bnx2 driver. | The Ortega spec describes a **richer** rule-element block on the BCM5719 APE (`REG_APE_RULE_ELEMN_CFG`, 32 rule elements, header types SOF/IP/TCP/UDP/DATA/ICMPv4/ICMPv6/VLAN with OFFSET in bytes). BCM5709 silicon predates the 5719 APE and is likely simpler, but a roughly equivalent rule block exists in the MCP. |

### Firmware/flash R/W primitives (NIC APE / MCP)

Note: BCM5709's coprocessor is called the **MCP** (Management Coprocessor),
not APE (APE was introduced on later NetXtreme I chips like 5719/5720). The
functional role is similar: it runs `NCSI 2.0.11` (the management firmware
blob), is reset-independent of the four MIPS RX/TX CPUs, and has bidirectional
register access to the rest of the chip.

| Capability | BMC-reachable? | Mechanism | Notes |
|-----------|----------------|-----------|-------|
| `loadfw` to RX/TX CPU | NO (host diag-fw only) | b57diag §10.47. Loads a file to TX or RX CPU memory and starts execution. Options: `-t` load to TX cpu, `-S` scratch pad, `-a<HEX>` scratch-pad address, `-s` don't start, `-i` no mem init. | This is the host-side "load attacker MIPS code on the NIC" primitive. Requires b57diag.bin running on the host (DOS/UEFI). Not BMC-reachable directly. |
| `loadbootcode <filename>` | NO (host diag-fw only) | b57diag §10.52. Executes bootcode from a file instead of from NVRAM. | Same as above. |
| `apectl` / `apeotpkey -p` (provision) | NO (host diag-fw only) | b57diag §10.66, §10.69. APE/MCP control: reset, halt, NOP-event, custom-event, RX-mgmt-filter on/off (`-f<HEX>`), WFI sleep modes, provision MC. | Reveals MCP capability surface. `apectl -f0/-f1/-f2` turns RX mgmt filtering off/on/all. |
| `apetest -w` (write apediag.bin to scratchpad) | NO (host diag-fw only) | b57diag §10.251 (page 183). Writes APE diagnostic FW to scratchpad without executing. | |
| **NCSI in-band firmware update (vendor sub-cmd)** | YES (theoretically) | Pushed in Broadcom/Dell DUPs via standard NCSI fw-update flow. Sub-cmd ID not in public docs. | The iDRAC9 has a working in-band path (`flash/pd0/network_config/*/NICSelection.sh`). On iDRAC6 1.70 the path is *present in the binary* (`G_au8NCSIHeaderDescriptionReq`/`Rsp` symbols in ncsiapptest) but the dispatcher to LOM may not initialize. **★★★ candidate**. |
| **NVRAM / SEEPROM access via NCSI** | UNVERIFIED | b57diag has `defragment` (§10.231), `secfg1-5`, `secfgsb1-3`, `secfghwsb1-3`, `secomp`, `seinit`, `seclock`, `seprotect`, `selclock`, `semap`, `setwol`, `setpxe`, `setasf`, `setipmi`, `setump`, `seotp`, `secfgsb1/2/3`, `secfghwsb1/2/3`, `iscsiprg`, `umpcfg`, `umpecho`. All host-side. The NCSI 2.0.11 firmware on the MCP itself **owns the NVRAM**; an OEM sub-cmd to write NVRAM through it is plausible (and would let the BMC persist an MCP firmware implant across power cycles — the goal of step 5 in `PoC-host-DMA-from-NIC.md`). | Strong probe candidate. |

### Diagnostic test modes (b57udiag-exposed — host-side only)

These confirm hardware capabilities but require b57diag running on the host
(typically from a FreeDOS / UEFI bootable USB). They are **not** directly
reachable from the BMC over NCSI — but they expose what silicon primitives
the NCSI dispatcher could be hiding.

| b57diag cmd | Reveals | What it tells us about the OEM cmd space |
|-------------|---------|--------------------------------------------|
| `dmaw -a<NIC-addr> -K<HOST-PHYS>` (§10.71) | NIC→host DMA write to arbitrary phys, "hang the system" mode | The MCP can target any 64-bit host phys with no validation. If NCSI exposes this, it is the one-shot win. |
| `dmar -K<HOST-PHYS>` (§10.72) | host→NIC DMA read from arbitrary phys | The mirror primitive. |
| `dma_h` / `dma_d` / `dma_alloc` (§10.73-75) | Dump / allocate DMA descriptors | DMA descriptor table is software-visible — the MCP can presumably build them. |
| `dmatest` (§10.129) | Full DMA test loop, options for length / NIC address / iteration / priority | |
| `bustest` (§10.133) | 260-pattern PCI bus DMA pattern test (256-1024 byte transfers) | Confirms the MCP's DMA path is exercisable at byte granularity. |
| `apeinfo` (§10.65) options `-r` (control regs), `-f` (mgmt filters), `-m` (mutex/shared mem), `-n` (random/NCSI), `-e` (Ethernet MAC), `-u` (USB/UMP), `-d` (DEV_Table), `-x`/`-i` (export/import mem,reg contents) | APE/MCP has direct register-space read **and write** capability through its dispatcher | The `-x`/`-C`/`-i` import/export of memory and register contents to a file is the smoking gun: **the MCP can read or write any register from a controlled host-side command**. If an OEM NCSI sub-cmd wraps the same dispatcher, the BMC has it too. |
| `apectl -e<HEX>` (§10.66) | Send APE custom event with `dd=data, ee=event id, ss=source` | The "custom event" surface is exactly the kind of thing an OEM NCSI sub-cmd would forward. |
| `apectl -A<DEC>` (§10.66) | Send ASF remote control (rst/off/on/pwrRst) | Power-state primitive — would let BMC force chassis reset via NIC if exposed. |
| `apectl -q/-s` (§10.66) | Query PLDM Numeric / State sensor by ID | PLDM-over-NCSI tunnel; less attack-relevant. |
| `apetest -t<1-9>` (§10.251) | APE CPU self-tests: G1 memory, G2 packet, G3 SMBus loopback, G4 GPIO, G5 event, G6 mutex, G7 timers, G8 GRC reset, G9 USB (UEFI only). | G2 "APE CPU Packet Test", G8 "APE CPU GRC Reset Test" are particularly interesting. |
| `apeping <host>` (§10.67) | APE issues an ICMP ping to a host (IPv4/IPv6/DNS) | Confirms the APE has full host-network-stack capability **independent of the host OS** — consistent with our observation of BMC `racadm ping 8.8.8.8 → 11.9ms reply` (Phase 2 of `dell-shared-nic-covert-channel.md`). |
| `aperead <start> <end>` (§10.68) | Read APE local view of memory | Read primitive. |
| `cpudtt` / `cpudrt` / `cputrace` (§10.48-50) | TX/RX CPU instruction trace | |
| `haltcpu -r/-t` (§10.51) | Halt RX or TX CPU | |
| `regdump` / `regcomp` / `regrestore` (§10.208-210) | Full chip register dump, compare, restore | |
| `setump` (§10.228) | Enable/disable UMP (Universal Management Port) — alternative mgmt mode | BNX2_MISC_ENABLE_*_UMP_ENABLE bit 27 — same hardware bit visible to driver. |
| `setipmi` (§10.227) | Enable/disable IPMI passthrough firmware | The BCM5709 has IPMI-over-NIC firmware mode (`BNX2_CONDITION_MFW_RUN_IPMI = 0x2000`) — see bnx2.h. T710 typically runs NCSI mode (`0x6000`). |
| `bcm5709-cpu-state` (custom tool, not b57diag) | Reads MCP scratchpad live | Confirmed `MCP_SCRATCH+0x30 = "NCSI 2.0.11"` on T710 onboard NIC. |

### Traffic interception / covert channel

| Capability | BMC-reachable? | Mechanism | Notes |
|-----------|----------------|-----------|-------|
| Receive BMC-destined unicast (inbound visible) | YES (proven) | NCSI sideband to MCP delivers any frame matching the BMC MAC filter | T710 dedicated NIC: works. Shared-NIC LOM: broken on iDRAC6 1.70. |
| Send BMC-originated packets (outbound invisible to host) | YES (proven) | MCP injects directly onto wire from sideband; bypasses host PCIe Tx ring | T710 dedicated NIC: works. `racadm ping 8.8.8.8` reaches the Internet, host sees nothing. |
| Steal host MAC's inbound traffic | UNVERIFIED on BCM5709 | Analog of i210 MDEF + MNGONLY: program a mgmt filter for host MAC + flag as "mgmt-exclusive" so it's not also DMA'd to host | Requires BMC-reachable Broadcom equivalent of MNGONLY. Probe target. |
| Magic-cookie flex filter for covert C2 | UNVERIFIED | Analog of i210 Flex 128-byte TCO filter. Broadcom's RPM rule slots may or may not have payload-depth pattern matching exposed via NCSI. | |
| BMC-to-host packet injection (via NIC) | UNVERIFIED | If the MCP can be made to write a forged Rx descriptor pointing at attacker phys + push a frame, it's an arbitrary-host-RAM write triggered by an inbound packet | Same root primitive as DMA section above. |

### Reset / persistence / power state

| Capability | BMC-reachable? | Mechanism | Notes |
|-----------|----------------|-----------|-------|
| Reset Channel (NCSI 0x05) | YES | Spec-defined. Forces channel to Initial State. | Can be used to wedge host link. |
| Set Link (NCSI 0x09) | YES | Force speed/duplex (10/100/1000, auto/force, pause) | |
| MCP graceful reset / halt (b57diag `apectl -r/-h/-R/-C`) | UNVERIFIED (host-only confirmed) | b57diag §10.66 | If wrapped in OEM NCSI cmd, BMC could reset just the management coprocessor (keeping host link up via main MIPS RX/TX CPUs). |
| ASF remote-control: power off / on / power-reset (b57diag `apectl -A0..-A3`) | UNVERIFIED (host-only confirmed) | b57diag §10.66, ASF Remote Control Request via APE | **★★★ if BMC-reachable**: NIC issues chassis power-cycle. Conventional path is BMC's own GPIO/PMBus to PSU; this would be NIC-as-actuator. Probe candidate. |
| Firmware-loadable MNGONLY values (i210-style flash-persistent silent intercept) | UNVERIFIED | The BCM5709's NCSI 2.0.11 firmware lives in NVRAM. An attacker who reflashes the MCP firmware can hard-code mgmt filters. | Persistent across reboots and OS reinstall. Requires the unverified "reflash MCP via NCSI" sub-cmd. |
| `apeotpkey -p/-u/-f` provision / unprovision MC | NO (host-only) | b57diag §10.69. Writes OTP keys. | One-shot. |
| `seotp` configure OTP (§10.229) | NO (host-only) | | |

---

## iDRAC6 FW 1.70 reachability matrix

What the WPCM450 / iDRAC6 1.70 NCSI stack actually does on the wire (from
`dell-ncsi-shared-nic-investigation.md` and our captures):

| NCSI cmd | iDRAC6 1.70 → pkg-0 (dedicated NIC) | iDRAC6 1.70 → pkg-1 (LOM/BCM5709C) |
|----------|--------------------------------------|--------------------------------------|
| Clear Initial State (0x00) | ✅ sent | ❌ never sent |
| Select Package (0x01) | ✅ sent | ❌ never sent |
| Enable Channel (0x03) | ✅ sent | ❌ never sent |
| Enable Channel Network TX (0x06) | ✅ sent | ❌ never sent |
| Set MAC (0x0E) | ✅ sent | ❌ never sent |
| Get Link Status (0x0A) | ✅ polled | ✅ polled (every ~1.6s, 4 identical pkts/burst) |
| Any OEM cmd (0x50) | UNKNOWN — never observed in our captures | not sent |
| Get Version ID (0x15) | UNKNOWN — never observed | not sent |

So even before any OEM-sub-cmd analysis, **iDRAC6 1.70 on T710 does not
initialize the LOM-fronting NCSI package at all**. The pkg-1 channel sits in
"Initial State" forever; standard cmds aren't sent, OEM cmds aren't sent. The
shared-NIC failure is not just about pass-through traffic — it's a complete
silence on the control plane for that package.

This means **today on T710 + iDRAC6 1.70**, the BMC can only OEM-talk to the
dedicated NIC (which is, ironically, also a Broadcom controller — usually a
BCM5709 or BCM5716 on the AMEA add-in card — and exhibits the same OEM
surface). For the host-DMA-via-LOM goal, the iDRAC firmware must be
upgraded/replaced or the WPCM450 NCSI driver bypassed (which our raw
AF_PACKET approach does for the Supermicro AST2400 successfully and is the
proposed path for T710).

**Raw AF_PACKET bypass (proposed):** the `ncsi-probe-oabi.c` and
`ncsi_raw_send.c` tools open `AF_PACKET / SOCK_RAW / ETH_P_NCSI` on the BMC,
construct frames byte-for-byte, and send to broadcast — bypassing the iDRAC
NCSI driver entirely. This is how the i210 MNGONLY attack worked on Supermicro
(the BMC's `ncsitool` ioctl silently drops OEM commands; AF_PACKET doesn't).
For Dell, **eth1 is the active sideband on the WPCM450** (not eth0, which is
the dead "DedicatedNICControl"-managed port). Probing pkg-1 (LOM) directly
via AF_PACKET on eth1 with raw NCSI frames is the unblocked path.

---

## Unknowns / gaps to probe next

Priority order, all on T710 + iDRAC6 1.70 via raw AF_PACKET on BMC eth1
(NCSI sideband):

1. **Get Version ID on pkg-1.** Send NCSI cmd 0x15 to channel `0x20` (pkg-1
   ch-0) and `0x21` (pkg-1 ch-1) from the BMC, observe the 40-byte response.
   If we get *any* response, pkg-1's NCSI 2.0.11 MCP is alive even though
   iDRAC6 never initialized it — meaning the BMC can drive it directly,
   bypassing iDRAC entirely. **Highest-value first experiment.**

2. **Send Broadcom OEM `Get MAC Address` (sub-cmd 0x01)** to all 4 channels of
   pkg-1. Confirms OEM dispatcher liveness and tells us which channels map to
   which physical LOM ports.
   ```
   NCSI cmd 0x50, payload:
     00 00 11 3D 01 00 00 00   ; IANA + sub-cmd 0x01 + 3 bytes pad
   ```
   Wire format per Linux kernel `ncsi_oem_gma_handler_bcm()` reference.

3. **Fuzz Broadcom OEM sub-cmd space 0x00..0xFF** on pkg-1 chan 0. Send
   `cmd=0x50, payload = IANA + sub_cmd + 0x00...` for each sub_cmd, log
   response codes. Spec says unknown OEM sub-cmds return Reason Code
   `0x000B Vendor/OEM-specific Reason Code` or `0x7FFF Unknown Command Type`.
   Anything that returns `0x0000 OK` with a non-trivial payload is a hit.
   Re-run for varying payload lengths (4, 8, 12, 16, 24, 32, 64 bytes) since
   the OEM dispatcher likely length-checks per sub-cmd.

4. **Look for register-window write sub-cmd.** Hypothesis: an OEM sub-cmd
   wraps `BNX2_PCICFG_REG_WINDOW_ADDRESS` + `BNX2_PCICFG_REG_WINDOW`. Send
   a probe that, if it works, sets `BNX2_DMA_CONFIG` (0x00000c08) to a known
   non-default value. Verify host-side by reading the same register over
   PCIe (`bcm5709-bar-dump` tool already on T710 at `/tmp/bcm5709-bar-dump`).
   Roundtrip change = win.

5. **Look for management-discard / sort-mode sub-cmd.** Send OEM cmds that
   write 1 into `BNX2_RPM_MGMT_PKT_CTRL.MGMT_EN` (bit 31) and verify
   host-side change. If a sub-cmd writes the SORT_USERn registers, we have
   the BCM5709 analog of i210 MNGONLY.

6. **NIC firmware update probe.** Look for a sub-cmd whose response is
   "ready to receive image" / "send next chunk". Patterns from other NCSI
   in-band fw updates (Mellanox SMAF, Intel) involve a multi-packet
   challenge/response with a length and offset. Don't actually push an image
   on a production NIC — just stop at the "ready" response if seen.

7. **`bcm5719-fw` (meklort) cross-reference.** The meklort reimplementation
   notes: *"NC-SI Handler: Functional ... Get Version ID: Not Implemented ...
   OEM Command: Not Implemented"*. Their clean-room implementation
   **deliberately skipped OEM cmd dispatch** — strong evidence that the OEM
   surface is non-trivial and Broadcom-proprietary. Their stage1/stage2 and
   APE source (if obtainable from
   https://github.com/meklort/bcm5719-fw) contains the
   register addresses and the dispatcher dispatcher entry points — would let
   us narrow #3's fuzz space substantially.

8. **iDRAC9 `ncsiapptest` recovery.** The stripped ARM ELF at
   `~/phd/bmc/dell/dell-oem-analysis/idrac9-extract/squashfs-root/bin/ncsiapptest`
   references `libncsi.so.1` and `libncsiapp.so.1`. The libs were not in the
   extracted squashfs — locating them (other iDRAC9 firmware version
   tarball, or in the running iDRAC9 binary) would give us the exact wire
   format Dell production code uses for Broadcom NCSI OEM commands. **Best
   single doc to chase.**

9. **NCSI 2.0.11 firmware image disassembly.** The 103KB
   `bnx2-mips-09-6.2.1b.fw` on T710 is the MIPS host-side firmware; the
   actual NCSI 2.0.11 MCP firmware lives in the BCM5709's NVRAM/SEEPROM.
   Reading NVRAM via b57diag's `nvm` commands and disassembling the OEM
   command dispatcher would give us the exhaustive sub-cmd list.

10. **Compare with Talos II / Blackbird BCM5719 in OpenPower.** The Raptor
    Computer Systems platforms run meklort's open replacement firmware, which
    publishes NCSI cmd handler source. On those platforms, OEM cmds *aren't
    implemented*. But the comparison gives baseline DSP0222 behavior we can
    fingerprint against.

---

## Strongest candidates for "BMC → host RAM via NIC DMA, no NIC firmware reflash"

Ranked:

1. **OEM register-write sub-cmd → write BD-ring base / DMA_CONFIG**
   (UNVERIFIED). Highest payoff (no reflash). Requires fuzz step #3-4 above.

2. **MCP firmware reflash via NCSI in-band fw-update sub-cmd** (UNVERIFIED).
   Crosses the "no firmware mod" line but is a one-shot, persistent, and
   well-supported attack profile that matches how legitimate Dell DUPs
   update LOM firmware in production.

3. **Forge Rx descriptor via `Set MAC` filter + register-write to RX BD base**
   (UNVERIFIED, depends on #1). Once an Rx BD points at attacker phys, any
   inbound packet to a BMC-controlled filter MAC writes attacker-chosen
   bytes to host RAM. The data path is "wire payload → DMA → host phys",
   triggered by a single inbound packet the attacker fully controls.

4. **Path A (driver state hijack) from host side, after BMC pivot to host**
   (out of scope per the "BMC → host RAM" framing, included for ranking
   completeness). The work in `~/phd/mobo/NIC/bcm5709/` already gets here
   from the host side.

---

## Source documents

| Path | What it contributed |
|------|---------------------|
| `/Users/zen/Downloads/FDOS_1_0_FINAL_B57udiag.pdf` (193 pages) | b57udiag tool reference: confirms `dmaw -K`/`dmar -K` arbitrary-host-phys DMA primitive; documents APE/MCP register access surface; UMP/IPMI/ASF firmware modes; loadfw/loadbootcode; CPU halt/trace/disasm; mgmt filter on/off via apectl; ASF remote power control; OTP/SEEPROM access. **No NCSI OEM sub-cmd IDs.** Only references PCI vendor 0x14e4 as "manufacturing ID" — IANA value not in the PDF. |
| `~/phd/bmc/NCSI_SECURITY_ANALYSIS.md` | DSP0222 baseline; Intel i210 OEM cmd 0x50 + IANA 0x157 details (MNGONLY, MDEF, OS2BMC, Shared MAC/IP, TCO Reset, Keep PHY Link Up Veto). Cross-applicable concept inventory — **Broadcom analog of each is the gap to probe**. |
| `~/phd/bmc/NCSI_EXPERIMENT_REPORT.md` | Live-validated host MAC interception on i210 via raw AF_PACKET from AST2400 BMC. Method directly portable to WPCM450 / BCM5709 once Broadcom OEM sub-cmds are known. |
| `~/phd/bmc/dell/dell-ncsi-shared-nic-investigation.md` | Confirms iDRAC6 1.70 NCSI driver finds pkg-1 (LOM/BCM5709) but **never initializes** it — Enable Channel, Set MAC, Enable TX are not sent. Kernel error message strings present in binary but code paths not reached. Cleanly excludes "iDRAC6 is doing something normal we'd see". |
| `~/phd/bmc/dell/dell-shared-nic-covert-channel.md` | Phase-2 evidence that BMC outbound via shared-NIC LOM is invisible to host (host sees inbound BMC traffic but no outbound). BMC reaches 8.8.8.8 with 11.9ms reply, fully invisible. Confirms working sideband from BMC despite pkg-1 init failure — **likely via pkg-0 path or via WPCM450 EMC indirection we haven't yet pinned down**. Worth re-investigating. |
| `~/phd/bmc/tools/ncsi_raw_send.c` | Reference implementation: raw AF_PACKET, EABI ARM, no-libc, sends Intel OEM 0x50 cmds. Trivially retargettable to Broadcom by swapping IANA `0x00000157 → 0x0000113D` and sub-cmd `0x0F → 0x01`. |
| `~/phd/bmc/dell/ncsi-probe-oabi.c` | OABI ARM (Dell iDRAC6 / kernel 2.6.23) version, on eth1, sends Get Version ID (0x15), decodes 40-byte response with Mfr ID at offset 32-35. **Already runnable on T710.** Drop in a Broadcom OEM cmd payload and we have probe #1-3 above. |
| `~/phd/bmc/scripts/dump_nic_mgmt_filters_py2.py` | Intel i210 BAR0 register reader — provides host-side ground truth for verifying NCSI register writes. **For BCM5709 verification we use `~/phd/mobo/NIC/bcm5709/bcm5709-bar-dump.c` and `bcm5709-indirect.c` instead** (already on T710 at `/tmp/`). |
| `/Volumes/yyy/phd/mobo/dell/upgrade-toolkit/docs/refs/meklort_bcm5719_README.md` | Clean-room BCM5719 firmware status: NC-SI handler functional, **Get Version ID and OEM Command explicitly Not Implemented**. Confirms that OEM cmd dispatch is the Broadcom-proprietary surface no open source has reimplemented. Source at https://github.com/meklort/bcm5719-fw is the best place to recover register-level details for our register-write hypothesis. |
| `/Volumes/yyy/phd/mobo/dell/upgrade-toolkit/docs/refs/ortega_rtg_spec.md` (BCM5719 RTG) | APE internals: TX_TO_NET / RX_FROM_NET memory ranges, RMU (RMII NC-SI peripheral), management filter blocks at `0xA004_8000`, rule element format (32 elements, HEADER=SOF/IP/TCP/UDP/DATA/ICMPv6/VLAN, OFFSET, OP=EQ/NE/GT/LT, MASK, PAT). **Roughly transferable to BCM5709 MCP** since both fronted NCSI 2.x; exact register addresses differ. |
| `/Volumes/yyy/phd/mobo/dell/upgrade-toolkit/docs/refs/delugre_hitb2011_broadcom.txt` | Original NetXtreme NIC DMA-to-host primitive. Slide 39: 1.modify phys addr in packet desc 2.modify packet contents 3.force send 4.→ arbitrary read/write. Slide 40: counter-measure = IOMMU. T710 has no IOMMU active. |
| `/Volumes/yyy/phd/mobo/NIC/bcm5709/bnx2.h` (BCM5709 driver header) | Provides register addresses: `BNX2_RPM_MGMT_PKT_CTRL` (0x180c) for mgmt enable/discard/sort/rule, `BNX2_RPM_SORT_USER0..3` (0x1820-0x182c) for VLAN/promisc/BC/MC enable, `BNX2_MISC_SM_ASF_CONTROL` (0x880) for SMBus/ASF, `BNX2_CONDITION_MFW_RUN_*` codes (0x2000 IPMI / 0x4000 UMP / 0x6000 NCSI / 0xe000 NONE), `BNX2_MCP_SCRATCH` (0x160000), `BNX2_SHM_HDR_*`. **These are the registers a register-write OEM sub-cmd would target.** |
| `/Volumes/yyy/phd/mobo/NIC/bcm5709/bnx2.c` line 6546-6547 | Shows mainline bnx2 driver dumping `BNX2_RPM_MGMT_PKT_CTRL` in debug — register is real and live on T710. |
| `/Volumes/yyy/phd/mobo/NIC/bcm5709/PoC-host-DMA-from-NIC.md` | Step-by-step Duflot port to BCM5709 / bnx2; confirms MCP_SCRATCH = "NCSI 2.0.11", T710 has no DMAR, BAR0 directly mmap-able. **The host-side companion to this NCSI-side reference.** |
| `/Volumes/yyy/phd/text-corpus/references/dmtf-ncsi-spec-DSP0222-v1.0.0.txt` | Reference DSP0222 v1.0 Table 17 (commands 0x00-0x1A + 0x50 OEM). Length checks waived for OEM. Reason code 0x0000-0x7FFF reserved, 0x8000-0xFFFF OEM-specific. |
| `/Volumes/yyy/phd/text-corpus/references/ncsi-spec-DSP0222-1.2.0.txt` | DSP0222 v1.2 adds cmds 0x1B Get Package Status, 0x25-0x2F PF/Partition/Boot config, 0x30-0x32 Module Mgmt Data, 0x33/0x34 Pass-through Mode Control, 0x35/0x36 VF Allocation, 0x38/0x39 InfiniBand, 0x47 Settings Commit, 0x48 Get ASIC Temp, 0x49 Get Ambient Temp. **Most not present in 2.0.11-era BCM5709**, but worth probing as gap fills. |
| `/Volumes/yyy/phd/nas-copy/toolz/sm/.build/src/linux-6.16/net/ncsi/internal.h` | `NCSI_OEM_MFR_BCM_ID = 0x113d`, `NCSI_OEM_BCM_CMD_GMA = 0x01`, `NCSI_OEM_BCM_CMD_GMA_LEN = 12`. **The only publicly-confirmed Broadcom OEM sub-cmd in mainline Linux is GMA = 0x01.** |
| `~/phd/bmc/dell/dell-oem-analysis/idrac9-extract/squashfs-root/bin/ncsiapptest` (stripped ARM ELF) | Confirms Dell ships an NCSI app on iDRAC9 with linker references to `libncsi.so.1` / `libncsiapp.so.1` (libs not in our squashfs extract). Symbol names: `G_au8NCSIHeaderDescriptionReq`, `G_u8NCSI_IID`, `discovery_ncsimacs`, `G_u8NDCDebug`, `G_u8NDCFA_UseOld`. Strings: "manufacturer id" (4 bytes worth = IANA), "payload version", "command id" — confirming Dell uses the standard sub-cmd-after-IANA layout. **Recovery of the lib is the single highest-leverage doc retrieval target.** |
| `~/phd/bmc/dell/dell-oem-analysis/idrac9-extract/squashfs-root/etc/sysconfig/NICSelection.sh` | The iDRAC9 NIC selection script — but the per-platform copies under `flash/pd0/network_config/{Pantera,Mojo,Icon,Orca}/NICSelection.sh` are all empty in our extract. The main script orchestrates `ifconfig`/`ifenslave` and reads `cfgNicSelection` and `dcs` features; **does not** itself send NCSI commands. The NCSI init is done elsewhere (almost certainly by `aim` / `osinet` daemons via `libncsiapp`). |
| `~/phd/bmc/dell/dell-idrac6-oem-commands.md` | iDRAC6 IPMI OEM cmd 0x06/0x52 `CmdMasterWR_OEM` — I2C master to internal buses, includes a "boot block flash" flag (bus=0xFF, slave=0xC2). **Not** the NCSI path, but interesting as a side channel — the iDRAC6 owns its own boot-block flash flag and at least one OEM IPMI cmd touches it. |

---

## Appendix: minimal Broadcom OEM probe payload (for retargeting `ncsi-probe-oabi.c`)

```c
/* Replace the existing payload in ncsi-probe-oabi.c::_start with:    */
/* NC-SI cmd 0x50 (OEM), payload = IANA 0x113D + Broadcom sub-cmd 1   */
/* (Get MAC Address). Expected response is OEM-formatted GMA reply.   */

pkt[18] = 0x50;                /* NC-SI command type = OEM */
pkt[19] = 0x21;                /* Channel ID: pkg-1, ch-1 (try 0x20-0x23) */
pkt[20] = 0x00; pkt[21] = 0x0C;/* payload length = 12 bytes */
/* skip 16 bytes of reserved (NCSI hdr is 16 bytes total) */
pkt[30] = 0x00;                /* IANA byte 0 */
pkt[31] = 0x00;                /* IANA byte 1 */
pkt[32] = 0x11;                /* IANA byte 2 */
pkt[33] = 0x3D;                /* IANA byte 3 -- Broadcom PEN 4413 */
pkt[34] = 0x01;                /* Sub-cmd: Get MAC Address */
pkt[35] = 0x00;                /* Padding / sub-cmd parameter */
/* remaining 6 bytes of payload zero */

/* Frame must be ≥ 60 bytes (Ethernet min). Send 64. */
```

To fuzz the sub-cmd space, loop over `pkt[34] = 0..255` and log
non-`0x7FFF`-and-non-`0x000B` response reason codes. Anything that returns
`0x0000 OK` with a non-zero payload length is a candidate hit.
