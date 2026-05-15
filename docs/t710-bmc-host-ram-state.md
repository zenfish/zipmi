# State of BMC → host-RAM via BCM5709 NIC on T710 / iDRAC6 1.70

Compiled 2026-05-14. Scope: research path "WPCM450 BMC issues commands that
cause BCM5709 to DMA into T710 host RAM, no firmware reflash on either side."
Sources: `~/phd/bmc/dell/*.md`, `~/phd/bmc/NCSI_*.md`, `~/phd/bmc/ncsi-*.md`,
`~/phd/bmc/nic-filter-deep-dive.md`. Nothing in this file is invented; each
claim is tied to a source paragraph or marked "not in source docs."

---

## Already proven / running on this exact hardware (T710 + iDRAC6 1.70 + BCM5709)

- **Shared NIC mode is wired up but the NCSI control plane is dead for the
  BCM5709 sideband.** Driver prints `NCSI: Second package Exist!` but never
  issues Clear Init / Select Package / Enable Channel for pkg 1. `eth3`
  stays `carrier=0`. (`T710-BUS-TOPOLOGY.md` "Verified Facts";
  `dell-shared-nic-covert-channel.md` §"Live NC-SI Traffic Capture" — only
  responses from Pkg1/Ch1 with "Link DOWN" and "Host NC Driver Not Active".)
- **Shared NIC mode passes data-plane traffic** (BMC IP 192.168.0.23 over
  LOM1) despite the broken control path: ICMP / IPMI / SSH / DNS / ping
  8.8.8.8 all work from the BMC. The host sees inbound-to-BMC packets but
  zero BMC-originated packets — confirms BCM5709 NCSI engine is bridging
  RX/TX. (`dell-shared-nic-covert-channel.md` Phases 1–2, "Asymmetric
  Visibility" / "Phase 2: BMC-Initiated Outbound".)
- **Dedicated NIC NCSI (eth2 on BMC Linux) is the active interface; eth1
  is raw NC-SI control to BCM5709 and is alive.** Live tcpdump on BMC eth1
  shows EtherType 0x88F8 Get Link Status responses with
  `Channel ID 0x21` (Pkg1/Ch1) every ~1.6s. So *some* NCSI control traffic
  is moving across the sideband even though the host-visible channel is
  down. (`dell-shared-nic-covert-channel.md` §"Live NC-SI Traffic
  Capture".)
- **BMC kernel NCSI driver identified.** `WPCM450 Ethernet NCSI driver Ver
  2.0 by NS24 Zmsong`. 11-step init sequence is implemented (mirrors what
  the AST2400 ftgmac100 driver does on Supermicro), strings recovered:
  `INTERFACE_INIT_REQUIRED`, `Scan all package`, etc. The driver was
  extracted from the BMC kernel image at `~/phd/bmc/dell/firmware-binaries/kernel.bin`.
  (`dell-shared-nic-covert-channel.md` §3 Phase 3.)
- **WPCM450 PECI master + I2C + GPIO + PWM + SPI + memdrv + KCS + USB
  gadget are all confirmed exposed as `/dev/aess_*` character devices
  from BMC userspace.** Including `/dev/aess_memdrv` (physical memory R/W
  from BMC userspace — but BMC's own RAM, not host RAM). (`dell-t710-live-analysis.md`
  §"BMC Device Drivers", §"fullfw Complete File Descriptor Map".)
- **The Dell shared-NIC asymmetric visibility result is reproduced**: 30
  packet capture shows 0 BMC-originated frames on host tcpdump even
  though BMC pings reach 8.8.8.8. Host has zero visibility on the
  outbound direction. (`dell-shared-nic-covert-channel.md` Phase 2 capture.)
- **`/dev/mem` on the BMC is readable + writable from root.** WPCM450
  SoC ID confirmed at 0xb0000000 = `0x0a926450`. PWM register
  0xb8007008 is writable (fan-speed manipulation confirmed working).
  `MemTest` userland tool on BMC handles arbitrary R/W. This is the same
  vector Pantsdown uses on AST2x00 to find the X-DMA registers — except
  the WPCM450 has no documented BMC→host-RAM DMA engine. (`dell-t710-live-analysis.md`
  §"BMC SoC Hardware Registers", §"BMC Physical Memory".)
- **IPMI default credentials work** (root/calvin). Remote racadm, SSH,
  HTTPS, raw IPMI all reachable on iDRAC6 192.168.0.23. (`dell-t710-attack-surface.md` §"Default Configuration".)

---

## Already proven on OTHER hardware (analogous, cousin reference)

- **Supermicro X11SSZ-QF + AST2400 + Intel I210 — BMC silently intercepts
  host inbound unicast.** BMC sends three NCSI OEM commands (Set MAC
  filter to host's own MAC, set MDEF0 to match it, set MNGONLY bit 0
  exclusive). Result: host tcpdump captures **zero packets** during 15
  ICMPs from external machine — 93.3% loss. Fully reversible. Tool is
  3.5KB statically linked ARM binary, ~10 min compile.
  (`NCSI_EXPERIMENT_REPORT.md` §5 Phase C; `NCSI_SECURITY_ANALYSIS.md`
  Appendix C.)
- **Same hardware: BMC modifies host NIC's MNGONLY register at will, no
  auth.** Set MNGONLY = 0xFF from BMC via NCSI OEM 0x50 / IANA 0x157.
  Verified host-side via PCI MMIO read: register actually changed.
  (`NCSI_SECURITY_ANALYSIS.md` Appendix B.)
- **AST2400 → I219-LM covert internet channel (different NIC, same chassis).**
  BMC manually re-enables an NCSI channel that firmware disables at boot,
  assigns IP, pings 8.8.8.8 / cnn.com, full TCP works. Channel uses
  AF_PACKET raw socket from BMC userspace. Host has zero visibility.
  (`ncsi-covert-channel-findings.md`.)
- **Pantsdown / AST2400 X-DMA on Supermicro is the textbook BMC→host-RAM
  primitive — but it uses the BMC SoC's own DMA engine, not the NIC.**
  The user already notes this. Not detailed in any of the read docs;
  user-provided context.
- **The Delugre 4-step DMA technique on BCM5709 (host-side ARM CPU
  inside the NIC issues PCIe DMA into host RAM via BusMaster) — known
  to be hardware-viable.** User-provided context. Not in source docs.

---

## Confirmed blockers on T710 specifically

| Blocker | Evidence | Source |
|---------|----------|--------|
| BMC's NCSI driver never issues Clear-Init/Select-Package/Enable-Channel for **pkg 1** of BCM5709 even though it discovers it. eth3 carrier=0. | dmesg shows "Second package Exist!" then nothing; eth1 traffic capture shows only Pkg1/Ch1 *response* frames replying to driver polls, but no Enable. | `T710-BUS-TOPOLOGY.md` "Verified Facts"; `dell-shared-nic-covert-channel.md` §"Live NC-SI Traffic Capture" |
| ICH9R SMBus (PCI 00:1f.3) **disabled by Dell BIOS** — no host-side I²C path to the LOM. | `T710-BUS-TOPOLOGY.md` Verified Facts | same |
| No LPC FWH bridge to host BIOS SPI — LPC reads of host SPI flash return 0xFF. | `T710-BUS-TOPOLOGY.md` Flash Isolation table | same |
| WPCM450 has **no documented X-DMA / PCIe-DMA engine**. PCI is only the iKVM VGA core, not a bus-master path into host RAM. | `T710-BUS-TOPOLOGY.md` BMC-Side block (PCI → VGA core only) | same |
| ICH9R SMBus controller disabled means no host-side i2c-i801 reads of BCM5709 NCSI sideband state. | `T710-BUS-TOPOLOGY.md` | same |
| `aess_i2cdrv` is held open by fullfw (busy) — can't bind from another process without stopping fullfw, which disables IPMI and likely the whole BMC. | `dell-t710-live-analysis.md` §"BMC Device Drivers" Note | same |
| BMC's `ncsitool` (if present) uses ioctl SIOCDEVPRIVATE to ftgmac driver — and on the Supermicro twin **silently drops OEM commands**. Likely same gap in WPCM450 driver — need raw AF_PACKET. | `NCSI_SECURITY_ANALYSIS.md` Appendix B "Technical Notes"; `ncsi-filter-attack.md` "ncsi_raw_send.c" rationale | same |
| WPCM450 has **one** MAC engine multiplexing eth0..eth5 via NCSI virtual interfaces — so if you bring up pkg1 from raw socket you're competing with the kernel driver's framing on the same wire. | `dell-shared-nic-covert-channel.md` §Phase 4 "The WPCM450 Has ONE MAC Engine" | same |
| **DMA into host RAM via standard NCSI is not a defined NCSI primitive.** DSP0222 commands listed in `NCSI_SECURITY_ANALYSIS.md` §2.3 do not include any memory-write operation. Pass-through is L2 frames only. | `NCSI_SECURITY_ANALYSIS.md` §2.3 table | same |
| Even on the i210 with full Intel OEM extensions, the documented capability set (`NCSI_SECURITY_ANALYSIS.md` §3) tops out at filter/MNGONLY/OS2BMC/Veto/TCO Reset/SetLink/Checksum offload. **No "write to host memory" Intel OEM cmd is listed.** | `NCSI_SECURITY_ANALYSIS.md` §3.1–§3.7 | same |

Bottom line on the "obvious" path: NCSI's pass-through and OEM cmd surface
does not include a host-RAM write. The host-RAM DMA on the BCM5709 has to
come from the NIC's *internal MIPS/ARM cores* using its *own* TX/RX
descriptor rings, or from b57diag-style register pokes — which is what the
Delugre/Duflot work showed.

---

## Plausible-but-untried paths that bypass the known blockers

Each item: name | premise | what it requires | risk to host | next experiment
| source.

### 1. Manual NCSI init for BCM5709 pkg1 from BMC userspace, bypass kernel driver

- **Premise**: The kernel driver never sends Clear-Init / Select-Package /
  Enable-Channel for pkg 1, but the sideband bus is alive (we see Pkg1
  responses). Raw AF_PACKET frames from BMC userspace bypass the driver's
  state machine entirely. This is exactly the Supermicro/AST2400 approach
  — provably works there.
- **Requires**: Cross-compiled ARM binary for ARM926EJ-S (the existing
  `ncsi_raw_send.c` targets armv5te which **matches** WPCM450 — see
  Compile/deploy section below). Open raw AF_PACKET on BMC eth1 with
  EtherType 0x88F8. Send the 11-cmd init sequence targeting pkg 1.
- **Risk to host**: Low. Activates a second NCSI channel; doesn't write
  host memory directly. Might confuse the kernel driver — see
  multiplexing-EMC blocker. Worst case: BMC NCSI control plane
  desyncs; reboot recovers.
- **Next experiment**: (a) port `ncsi_raw_send.c` to WPCM450, (b) send
  Select-Package(1) + Clear-Init + Enable-Channel(pkg1/ch0), (c) re-check
  eth3 carrier on BMC and host-side `ip link` for em2.
- **Source**: blocker doc `T710-BUS-TOPOLOGY.md`; primary technique
  `ncsi-filter-attack.md`, `NCSI_SECURITY_ANALYSIS.md` Appendix B.

### 2. BCM5709 OEM NCSI command surface — Broadcom equivalent of Intel 0x50/0x157

- **Premise**: All the host-RAM-adjacent capability in the Intel docs is
  *OEM*, not base DSP0222. Broadcom has its own IANA (4413) and presumably
  its own OEM cmd set on the 5709 NCSI engine. The `dump_nic_mgmt_filters_py2.py`
  / b57diag work in prior research may have documented some of them.
- **Requires**: A capture (or RE) of Broadcom NCSI OEM cmds. b57diag's
  source if obtainable. Or: brute-force the OEM cmd space (cmd 0x50,
  IANA 4413, sub-cmd 0..255) from BMC raw socket and log responses —
  same fuzzing approach the Dell OEM 0x30 enumeration used.
- **Risk to host**: Low for read cmds, unknown for writes. Some Broadcom
  OEM cmds may trigger NIC TX/RX engine state changes that could glitch
  host networking.
- **Next experiment**: brute-force NCSI cmd 0x50 / IANA 4413 / sub 0..255
  from BMC raw socket against the BCM5709. Catalogue responses. Build
  this on top of the (un-ported) `ncsi_raw_send.c`.
- **Source**: not in source docs — analogous to Intel approach in
  `ncsi-filter-attack.md`.

### 3. b57diag-style register access from the host side (out-of-NCSI)

- **Premise**: BCM5709 has BusMaster DMA controllable via BAR0 MMIO from a
  host root process. `b57udiag -K DMAW` does "DMA write to absolute
  address" already. The premise of the project is doing this *from* the
  BMC, but the host-side primitive can be used to (a) prove the DMA works
  on this exact NIC silicon, (b) characterize which BAR offsets the BMC
  would need to drive, (c) build the same MMIO command stream on the
  BMC if any BAR-equivalent is reachable.
- **Requires**: root on T710 host. `b57udiag` / `b57tool` / `bcmregtool`
  (meklort). User's pyproject.toml mentions `igc.py` and `bmc_id` —
  unrelated.
- **Risk to host**: HIGH. Misconfigured DMA write can corrupt kernel
  memory and panic the host. Use a known scratch buffer (mlock'd page,
  physical address from /proc/self/pagemap).
- **Next experiment**: on the T710 host (192.168.0.22), run
  `b57udiag -K DMAW <safe_phys_addr> <pattern>` and validate via
  `/proc/iomem` + a kernel module dumping the target page. Establish a
  *baseline* of which commands the NIC accepts before attempting the
  BMC-side equivalent.
- **Source**: user-provided context (Delugre 4-step technique, b57udiag
  DMAW -K). Not in the read docs.

### 4. Bring BCM5709 NCSI control via the ALREADY-WORKING dedicated-NIC path

- **Premise**: BMC's eth2 (dedicated NIC NCSI to the Avocent AMEA card) is
  working. If the BCM5709 sideband is also wired and `eth1` is alive (it
  is — we see Get Link Status responses), there's nothing in the docs
  saying you can't issue ad-hoc NCSI cmds on eth1 outside the kernel
  driver's lifecycle. The driver just hasn't *enabled* the channel.
  Avocent NCSI driver may also gate the OEM 0x50 cmd path the way
  ftgmac.ko does — confirming this gates Approach #1.
- **Requires**: AF_PACKET on BMC eth1; sanity test by sending Get
  Capabilities to pkg 0 (already up) and verifying the response.
- **Risk**: Low.
- **Next experiment**: AF_PACKET sniff on eth1 to capture the driver's
  init for pkg 0, then replay-and-fuzz against pkg 1.
- **Source**: `dell-shared-nic-covert-channel.md` §Phase 4 packet count
  evidence (eth1 carries 1400 extra TX packets = NCSI control).

### 5. Direct BCM5709 register access from BMC via a sideband other than NCSI

- **Premise**: BCM5709 typically exposes a serial mgmt interface (SMI/MDIO
  for PHY) and may expose its internal CPU's debug/JTAG. The 5709's
  sideband bus is shared between NCSI traffic and (on some board layouts)
  a separate SMBus/I²C channel for FRU/PHY access. The T710 board may or
  may not wire any of these to the WPCM450.
- **Requires**: schematic-level info on the T710 LOM riser. Not in source
  docs; would need PCB inspection or Dell service manual.
- **Risk**: Low to recon, unknown to write.
- **Next experiment**: Cap-scope or visual trace from BCM5709 mgmt pins
  to nearest WPCM450 pin. Out of scope for software-only research.
- **Source**: not in source docs.

### 6. WPCM450 USB gadget → host USB stack as a memory write vector

- **Premise**: BMC already presents itself as USB mass storage + HID to
  the host via `g_mass_storage` / `g_kbdmouse`. USB *is* a DMA-capable
  bus on the host — the EHCI controller will DMA into host RAM for any
  device that talks to it. A custom gadget could request large bulk
  transfers; the host EHCI driver allocates buffers and the BMC fills
  them. Not arbitrary-address (host kernel chooses the buffer), but it's
  a real host-RAM write path the BMC fully controls.
- **Requires**: Replace `g_mass_storage` with a custom gadget on the BMC
  (cross-compile + insmod). Or just: write to `/dev/avct/usb_iface*` to
  fill virtual-media buffers and reason about where they land.
- **Risk to host**: Low. Host USB driver isolates buffers.
- **Next experiment**: on host, `lsusb -v` + watch `dmesg` while BMC
  writes patterns to virtual-media gadget. Determine if any host
  driver buffer-overflow or DMA-coherence quirk gives a write-anywhere
  primitive.
- **Source**: `dell-t710-live-analysis.md` §"BMC Kernel Modules",
  §"Keystroke Injection via USB HID".

### 7. PECI mailbox writes from BMC → CPU registers → coerce CPU to fetch from attacker-controlled address

- **Premise**: WPCM450 has direct PECI to both Xeon sockets (no IOH/ICH
  in the path). `DellCmdPECI_MailBox_WriteRead` (NetFn 0x30 cmd 0x8B)
  exists. The PECI MSR/CSR write side could be used to manipulate
  Nehalem-EP power/uncore CSRs. *Not* a direct host-RAM write, but a
  CPU-state manipulation path independent of the NIC.
- **Requires**: Payload format for cmd 0x8B (not yet reversed —
  `dell-t710-attack-surface.md` Critical #1 lists this as needing RE).
- **Risk to host**: HIGH. PECI writes to CSRs can lock CPU or trigger MCE.
- **Next experiment**: RE `DellCmdPECI_MailBox_WriteRead` in fullfw
  (already extracted). Map opcode bytes. Start with reads. Out of
  scope for the NIC-DMA project but logged as alternate primitive.
- **Source**: `dell-t710-attack-surface.md` §3 row 0x8B, §8 Critical 1.

### 8. KCS / BT host IPMI interface as a (very slow) host-RAM write

- **Premise**: KCS lets the host driver `ipmi_si` poll IPMI messages from
  the BMC. The BMC can write to KCS data registers, and the host kernel
  driver copies those bytes into kernel buffers. This is a host-kernel-
  controlled write, not arbitrary. But IPMI message buffers on the host
  side have known structures that can be confused by malformed seq
  numbers etc. Historical: there *have* been ipmi_msghandler vulns —
  could be a memory corruption primitive at the OS layer.
- **Requires**: pick a CentOS 6.7 kernel (2.6.32-573.7.1.el6) and look
  for known CVEs in `ipmi_si` / `ipmi_msghandler` for that version.
- **Risk to host**: Crash on first attempt.
- **Next experiment**: `searchsploit ipmi_si` for that kernel. Not in
  source docs but trivially answerable.
- **Source**: `T710-BUS-TOPOLOGY.md` Bus Summary table.

### 9. Re-enable ICH9R SMBus → use NIC-side SMBus mgmt for BCM5709 reg access

- **Premise**: ICH9R SMBus is *disabled by BIOS* but the controller is in
  silicon. If you can re-enable it via SMI (set PMBase bits) you might
  expose a host-side I2C path to BCM5709. Doesn't help the BMC-only
  threat model but useful for characterization.
- **Requires**: kernel-side or SMM-side SMBus enable. Possibly via Dell
  OEM 0x30 cmd that triggers `DellSMIBIOS()`.
- **Risk to host**: Medium — re-enabling SMBus mid-runtime is undefined.
- **Source**: `T710-BUS-TOPOLOGY.md` Open Question 3.

### 10. Lifecycle Controller / MASER write of malicious NIC config

- **Premise**: T710 iDRAC6 has Lifecycle Controller storage (lcl.img).
  Modifying NIC config (NCSI MNGONLY-equivalent) persistently via LCL
  → reboot → NIC boots with intercept rules. *Doesn't* reflash NIC
  firmware itself.
- **Requires**: LCL config format RE. lcl.img already in
  `~/_puff/ipmi/Dell/dumps/lcl.img` (1MB).
- **Risk**: Medium-low.
- **Source**: `dell-cmd-deep-dives.md` MASER glossary; not directly
  tied to NIC config in source docs.

### 11. Use DellCmdSetThreshold / DellAbsFan_WritePROCHOT as side channels

- **Premise**: Not a memory write — out of scope for project. Logged for
  completeness as the only confirmed BMC→host hardware-state manipulation
  paths in the source docs that *don't* depend on the NIC.
- **Source**: `dell-t710-attack-surface.md` §6.

### 12. Boot-from-iSCSI / PXE plus iDRAC virtual media → run attacker code in host context

- **Premise**: This is the documented Dell attack chain that *does* give
  full host-RAM access — but it requires a host reboot and an OS load,
  which is louder than the silent-DMA primitive the project is after.
  Listed only to explicitly de-scope.
- **Source**: `dell-t710-attack-surface.md` §8 Critical 3.

---

## Specific code/tools that already exist for next steps

All paths are absolute. Status column indicates compile/run state per the
source docs.

| Tool | Path | Purpose | Compiled? | Run on which HW? |
|------|------|---------|-----------|------------------|
| `ncsi_raw_send.c` | `~/phd/bmc/tools/ncsi_raw_send.c` | Low-level NCSI frame sender/receiver via AF_PACKET on BMC. Bypasses kernel driver. EtherType 0x88F8. | Yes (ARM `armv5te`, `-nostdlib -static`) | AST2400 (Supermicro). **Not yet on WPCM450 — but armv5te matches ARM926EJ-S, so binary should run.** |
| `ncsi_full_attack.c` | `~/phd/bmc/tools/ncsi_full_attack.c` | 5-mode attack: reset / port-intercept / OS2BMC / shared-MAC / full-duplex / dump. Calls Intel 0x50/0x157 OEM cmds. | Yes | AST2400 + Intel I210. Not on T710. |
| `ncsi_oem_attack.c` | `~/phd/bmc/tools/ncsi_oem_attack.c` | Intel-OEM-specific MNGONLY set/get. | Yes | AST2400. |
| `ncsi_cleanup.c` | `~/phd/bmc/tools/ncsi_cleanup.c` | Reset NCSI filters to factory defaults. | Yes | AST2400. |
| `ncsi_reset.c` | `~/phd/bmc/tools/ncsi_reset.c` | NCSI channel reset utility. | Yes (listed). | AST2400. |
| `ncsi_host_mac_intercept.c` | `~/phd/bmc/tools/ncsi_host_mac_intercept.c` | Demo: BMC programs host MAC into mgmt filter + MNGONLY. The 22:32-22:34 PDT 2026-03-22 experiment. | Yes | AST2400 + I210. **Critical reference for adapting to BCM5709 if a Broadcom-OEM-equivalent of MNGONLY exists.** |
| `dump_nic_mgmt_filters_py2.py` | path not stated in read docs — search `~/phd/bmc/tools/` | Per user prompt: dumps NIC mgmt filter state. | Unknown | Unknown |
| `xdma-host-rw.py` | per user prompt | Pantsdown X-DMA equivalent | Unknown | AST2400 (likely) |
| `ncsi-probe-oabi.c` | per user prompt | NCSI probe for OABI ARM (older ABI — may be needed for older BMC kernels) | Unknown | Unknown |
| BMC kernel image | `~/phd/bmc/dell/firmware-binaries/kernel.bin` | 4.2 MB. Contains WPCM450 NCSI driver source-derived strings. | RE-able with Ghidra / r2 | T710 BMC. |
| `aim` daemon binary | `~/phd/bmc/dell/firmware-binaries/aim` (216 KB) | Avocent Integration Module — owner of NCSI channel state | RE-able | T710 BMC. |
| `osinet` | `~/phd/bmc/dell/firmware-binaries/osinet` (63 KB) | Network config daemon | RE-able | T710 BMC. |
| `fullfw` | `~/_puff/ipmi/Guest/Dell/bin/fullfw` (1.72 MB) | Main IPMI daemon. Contains `DellCmdPECI_MailBox_WriteRead` and the entire Dell OEM 0x30 handler tree at addresses listed in `dell-t710-attack-surface.md` §5. | Already RE'd in part — see `~/phd/bmc/dell-fullfw-decompiled/` and `~/phd/bmc/dell-smi-trigger.md` | — |
| `MemTest` | already on BMC (busybox-companion) | Physical R/W of BMC SoC registers from BMC root shell | Already running | T710 BMC (confirmed fan/PWM writes). |
| `b57udiag` | per user prompt — typically packaged with Broadcom NetXtreme II diag suite | DMAW -K = host-side DMA write to absolute address from root | Unknown if currently installed on host | T710 host (CentOS 6.7) — needs install |

### Build command (works for AST2400, should work for WPCM450)

```
arm-linux-gnueabi-gcc -nostdlib -static -march=armv5te -marm -Os \
  -fno-builtin -o ncsi_raw ncsi_raw_send.c
```

Source: `ncsi-filter-attack.md` build instructions. ARM926EJ-S is armv5tej,
which is a strict superset of armv5te — the AST2400 binary will run on
T710 WPCM450 modulo the actual NCSI ioctl/socket differences (which there
shouldn't be — AF_PACKET is generic).

### Deployment vector for T710 BMC

- NFS mount used on AST2400 per `NCSI_EXPERIMENT_REPORT.md` §3.
- T710 BMC has `/tmp` tmpfs writable; SCP via SSH (root/calvin) works
  (`dell-t710-live-analysis.md` confirms SSH access).
- `~/puff/toolz/` mount-point convention is for the Supermicro BMC, not Dell.

---

## Open questions answerable by a single experiment

Ranked by leverage (impact ÷ effort):

1. **Does the AST2400 `ncsi_raw_send` binary actually execute on the T710
   WPCM450?** scp it, run it on BMC `eth1`, capture output. If yes, the
   entire AST2400 attack toolchain is portable to T710 once we know what
   the BCM5709 OEM cmd set looks like. (1 hour)
2. **Will BCM5709 accept NCSI Select-Package(1) + Clear-Init +
   Enable-Channel(1) from raw AF_PACKET on BMC eth1, given the kernel
   driver didn't?** This is the entire "shared NIC unbreaks itself"
   scenario. If yes, eth3 comes up and pkg-1 is usable. (2 hours after #1)
3. **What does BCM5709 return to NCSI Get Capabilities + OEM cmd 0x50
   with Broadcom IANA 4413?** Catalogues the Broadcom OEM cmd surface.
   (1 day brute-force after #2)
4. **Is there a Broadcom-OEM equivalent of Intel MNGONLY, OS2BMC, or
   shared-MAC?** If yes, the AST2400 attack class works on BCM5709. If
   no, the project pivots to in-NIC code execution (Delugre-style). (1
   week of RE on `bnx2-utils` / b57diag / open source bnx2 driver +
   the brute-force from #3)
5. **Can `b57udiag -K DMAW` actually write to a known scratch buffer on
   the T710 host?** Validates the underlying NIC DMA primitive
   independent of the BMC. (2 hours, host-side, root required)
6. **What address space can `/dev/aess_memdrv` reach on the BMC?** Just
   BMC RAM, or memory-mapped PCI? If the WPCM450 has any window into
   the PCI bus that hosts the BCM5709, that's a register-level path.
   (1 hour — `cat /proc/iomem` on BMC, then probe with MemTest)
7. **What does the host see when the BMC USB-gadget initiates a 4 KB
   bulk write that the host EHCI driver DMAs into kernel buffers?** Is
   the destination kernel slab predictable enough to be a write
   primitive? (1 day)
8. **RE the payload format of NetFn 0x30 cmd 0x8B
   (DellCmdPECI_MailBox_WriteRead) and verify with a benign PECI read
   first.** Out of scope for NIC project but the highest-leverage
   non-NIC primitive on this box. (3 days RE in `fullfw`)
9. **Is there any path from `aim` / `osinet` userspace that issues raw
   NCSI cmds (as opposed to going through the kernel driver)?** RE
   the extracted binaries. If yes, the userspace path is the cleanest
   way to issue arbitrary NCSI from a "supported" code path. (2 days RE)
10. **Does the WPCM450 have an undocumented DMA controller (Nuvoton
    PDMA / NPCM-family DMA engine)?** Probe `/dev/mem` and known
    Nuvoton MMIO ranges. Compare with neuschaefer/wpcm450 wiki.
    (1 day reading + 1 hour probing)

---

## Notes on what was explicitly NOT found in the source docs

- No mention of any BCM5709 NCSI OEM command surface (Broadcom-side
  parallel to Intel 0x50/0x157). Either it doesn't exist, or it was
  never RE'd in the docs read. Worth checking the public b57diag / 
  bnx2 sources before fuzzing blind.
- No claim that WPCM450 has X-DMA or any PCIe DMA master. Topology
  doc explicitly says BMC PCI = iKVM VGA core only.
- No published RE of the Dell `dell-fullfw-decompiled/` NCSI section.
  The decompiled tree referenced in `dell-t710-attack-surface.md` §9
  focuses on SMI / power / PECI, not NCSI.
- No record that `dump_nic_mgmt_filters_py2.py`, `xdma-host-rw.py`,
  or `ncsi-probe-oabi.c` (named in user prompt) have been compiled or
  run on T710 — they were not described in any of the 11 docs read.
