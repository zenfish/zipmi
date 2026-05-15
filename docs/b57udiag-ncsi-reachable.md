# b57udiag NCSI-reachable / BMC-reachable primitives

Source: WikiLeaks `FDOS_1_0_FINAL_B57udiag.pdf` ("Broadcom NetXtreme Diagnostic User's Guide", 10,616 line pdftotext extract at `/tmp/b57udiag.txt`). All quotes verbatim with line numbers.

## TL;DR (3 lines)

1. `b57udiag` is unambiguously a **host-side DOS/UEFI/Linux diagnostic** that drives the NIC through PCIe BAR0, the APE shell, and DMA — there is **no command in the entire guide that takes its input over the NCSI sideband.** NCSI/BMC is treated only as a *configuration target* (slave addresses, RMII vs SMBus, NVRAM keys) and as a *firmware feature flag* (`setipmi -e`, `setump -e`, `setasf -e`, `apeotpkey -p`).
2. The doc does **not document any Broadcom NCSI OEM sub-codes, IANA 0x113D, MFG-ID, "vendor command", "OEM command", "remote diagnostic", or "sideband injection" primitive** — searches returned zero hits. The only OEM-shaped surface this tool *creates* is whatever the IPMI/UMP/DASH/ASF firmware images ship — `b57udiag` enables those bundles but does not enumerate their wire protocol.
3. The genuinely interesting BMC-relevant primitive is **`mancfg` / `bmcfg`**: it provisions, encrypts, signs, and ships the **APE_CFG** record (including server cert + private key) and can `apeotpkey -p` "Provision management controller". Owning a host with `b57udiag` lets you re-key the NIC's management persona — that is the BMC-trust attack surface this tool exposes, not a runtime NCSI command channel.

## Cmds where the doc *explicitly* mentions NCSI/BMC/sideband as an input path

| cmd | section | quote | what this actually gives the BMC |
|---|---|---|---|
| `apeinfo -n` | 10.65 / L5757 | `-n   Show random#/NCSI` | Host-side display of NCSI state read out of APE. Not a BMC input. |
| `apeinfo -f` | 10.65 / L5753 | `-f   Show receive management filters` | Host can inspect the mgmt-traffic filter table the BMC sees. Read-only display. |
| `apectl -f<HEX>` | 10.66 / L5809 | `-f<HEX>   turn rx mgmt filter all(-f2)/on(-f1)/off(-f0)` | Host-side toggle of whether mgmt traffic flows to the APE / BMC at all. **From the BMC side this is the off-switch on the host's side.** |
| `apectl -A<DEC>` | 10.66 / L5850 | `-A<DEC>   send ASF remote control request (rst:0, off:1, on:2, pwrRst:3)` | **Host emulating the remote-management controller**: tells APE to issue ASF chassis reset/off/on/powerRst. Inverse of what we want, but documents the ASF chassis-control event ID space. |
| `apeotpkey -p` | 10.69 / L5880 | `-p   Provision management controller` | Burns OTP keys that bind the NIC's management-controller persona. One-way trust seed. |
| `apeotpkey -u` | 10.69 / L5882 | `-u   Unprovision management controller` | (unverified — OTP is one-time; this likely revokes via a kill-bit. Doc gives no detail.) |
| `setipmi -e/-d` | 10.227 / L9610–9621 | `Enable/Disable IPMI Passthrough Firmware` | Turns on the **IPMI passthrough fw** in NVRAM. Once on, the NIC speaks IPMI to the BMC over the sideband. See next section. |
| `setump -e/-d` | 10.228 / L9623–9634 | `Enable/Disable UMP` | Turns on Universal Management Port fw in NVRAM. |
| `setasf -e/-d/-q` | 10.35 / L5165–5185 | `Enable/Disable ASF`, `-q  Query Enable State` | Turns on Alert Standard Format fw (RMCP/PET sender). |
| `apeping <host>` | 10.67 / L5854–5860 | `Send APE event to ping host from APE. The host can be IPv4, IPv6 address or host name for a DNS lookup.` | **APE→external ICMP**. Demonstrates APE has IPv4/v6 stack + DNS; meaning the management firmware on the chip is reachable from external network *to itself* (it can resolve names). Not "BMC pings host" — "APE pings anything". |
| `seprg -a -b -k300 dashfw.rom` | 10.13.x / L4644-4651 | `Program NVRAM with APE DASH firmware dashfw.rom as APE UPDATE image and pad up to 300kilo bytes. Padding and backup image is needed to enable out-of-band DASH` | Host installs the **out-of-band DASH** firmware payload. This is the actual BMC-reachable management firmware blob; b57udiag is its loader, not its protocol-level driver. |
| `mancfg` (a.k.a. `bmcfg`) | 10.16 / L4889-4951 | imports/exports/encrypts `APE_CFG`, `-C  Create self-signed server certificate and private key`, `-p  Export public key to DER encode file` | **The management-firmware cert + key store.** Whoever can run this on the host owns the BMC-side authentication material. |
| `apeinfo -C` | 10.65 / L5781 | `-C   Export bmcfg buffer (scratchpad->file)` | Dumps the bmcfg scratchpad — i.e. exfil of the runtime management-config blob. |

Nothing else in the doc indexes the strings *NCSI*, *BMC*, *sideband*, *out-of-band*, *passthrough*, or *management controller* in the description of a command.

## SETIPMI / IPMI Passthrough Firmware — full spec

Verbatim (§10.227, L9610-9621):

```
10.227   setipmi
     Command: setipmi
     Description: Enable/Disable IPMI Passthrough Firmware
     Syntax: setipmi
     Options:
                  -e                Enable IPMI Passthrough Firmware
                  -d                Disable IPMI Passthrough Firmware
```

That is **all** the doc says about `setipmi`. There is no sub-command, no register list, no transport spec, no command code table. "IPMI Passthrough Firmware" is a feature flag in NVRAM controlling whether the IPMI-fw image (loaded via `-pipmi <filename>` / `-uipmi <filename>`, §10.5 area, L1606-1614) is enabled at boot.

Related but distinct primitives that touch the same firmware:

| ref | quote | line |
|---|---|---|
| §10.5 cmdline | `-pipmi <filename> used for field program of IPMI firmware` | L1606 |
| §10.5 cmdline | `-uipmi <filename> used for field program of IPMI firmware ... The firmware is programmed into a/the device/s specified by "-c" option switch if IPMI firmware is` | L1611-1614 |
| §10.5 cmdline | `-ipmi <value> : Enable/Disable (value = 1/0) IPMI in manufacture mode` | L2066 |
| §3 menu opt 24 | `Advanced firmware feature (ASF/IPMI/UMP)` | L3119, L3380 |
| §3 menu opt 51 | `Pri. Port SMB Address (ASF/IPMI)             : A4` | L3162 |
| §3 menu opt 52 | `Sec. Port SMB Address (IPMI)                 : A6` | L3163 |
| cli flag | `-a   ASF/IPMI SMB Address for Pri. Port` (§10.45 area, L5415) |
| cli flag | `-b  IPMI SMB Address for Sec. Port` (L5417) |

**Bottom line.** `b57udiag` does *not* expose the IPMI passthrough wire protocol. It only flips the NVRAM bit that loads the passthrough firmware and sets the SMBus slave addresses (default Pri=`0xA4`, Sec=`0xA6`) that the BMC then talks to. The actual passthrough protocol is in the IPMI fw image — opaque to this guide.

## UMP commands — full spec

UMP = **Universal Management Port** (Broadcom's pre-DASH management fw, runs on the same APE/SMBus path as IPMI passthrough; addressed via the same Pri/Sec SMBus addrs).

| cmd | §/L | quote |
|---|---|---|
| `umpcfg` | 10.226 / L9564-9598 | `Configure UMP in NVRAM`. Sub-menu items: `1 Enable/Disable SetLink`, `2 Enable/Disable RDIStallTimer`, `3 Set RDIStallTimerValue`, `4 DisableHostHashTable`, `5 Enable/Disable HostEchoControl`, `6 Enable/Disable Exceed_375ma_rule`, `7 Link Speed` (with sub: 10/100, ALL, 10, 100, 1000, Duplex, Auto/Force Mode, Pause Capability). |
| `umpecho` | 10.225 / L9532-9562 | `Enable/Disable UMP Echo Test function in UMP Firmware. It requires either ump14a.bin/ump14b.bin test firmware or UMP Firmware.` Options: `-o` run echo test, `-c` Debug display of SRAM address 0xC00, `-i` Debug display of CPU code loading, `-a` Debug prompt after CPU code loading, `-e` Enable New UMP Echo Test in UMP Firmware, `-d` Disable New UMP Echo Test. |
| `umplb` | L2642 listing only | `UMP Loopback Test` — listed in cmd index, no dedicated section in the PDF extract. |
| `setump` | 10.228 / L9623-9634 | `Enable/Disable UMP`. Options: `-e` Enable UMP, `-d` Disable UMP. |
| `apeinfo -u` | 10.65 / L5763 | `-u   Show USB/UMP ctrl registers` — host-side register dump only. |
| cmdline `-pump <file>` | §10.5 / L1368-1372 | `Program UMP firmware`. Example: `b57diag –e <code> -c 0 –pump ee5714c1.00`. |
| cmdline `-pump1 <file>` | L1373-1374 | `Program UMP firmware only` (adds UMP fw to existing NVRAM). |
| cmdline `-uump <filename>` | L1353-1356 | `used for field program of UMP firmware … field upgrade … if UMP firmware is` (sentence truncated in source). |
| cmdline `-u <value>` | L1376 | `Enable/Disable (value = 1/0) UMP in manufacture mode`. |

**BMC-reachable register R/W via UMP?** No — the doc never describes UMP as a "register poke" channel. UMP is a *managed-link config protocol* (SetLink, RDIStallTimer, HostHashTable, EchoControl) over the SMBus passthrough. `umpecho` is an echo loopback for verifying the SMBus path between BMC and NIC, *not* a generic R/W primitive. The NIC's UMP error codes confirm this is a packet protocol (`ERR_UMPLB`=156, `ERR_UMPCTRL` "UMPCtrl 0x5F0 = XXXX" L10325-10326, `ERR_UMP_VS_DEV` "UMP VS Device Error" L10339).

`apeinfo -u` will read the USB/UMP ctrl registers but that is host-side, not BMC-side.

## APE-side primitives reachable from NCSI (if any)

Searched: `apectl`, `apeping`, `aperead`, `apetest`, `apeotpkey`, `apelog`, `ape mailbox`, `ape event`, `ape scratchpad`. Every documented option is invoked from the host shell; no reverse direction is documented.

- `apeping <host>` — verbatim L5854-5860: *"Send APE event to ping host from APE. The host can be IPv4, IPv6 address or host name for a DNS lookup."* This is **APE→network ICMP**, triggered by a host shell command. There is no documented *external→APE* trigger primitive in this PDF. The interesting capability that *leaks* from this entry is that **APE has a full TCP/IP+DNS resolver online** when management fw is loaded — which means whatever IP the management fw is bound to is itself reachable from the wire (sideband or external) per whatever ACL DASH/IPMI fw enforces. None of that is documented here.
- `apectl -e<HEX>   send APE custom event ddeess (dd=data, ee=event id, ss=source)` (L5815) — generic APE event-injection primitive. The `ss=source` byte demonstrates the APE event model has a *source* field (likely host vs MAC vs management) but the doc does not enumerate values. **Unverified open question.**
- `apectl -n   send APE NOP event (are you alive?)` (L5805), `-r reset (graceful)` (L5807), `-R reset block (ungraceful)`, `-C reset CPU`, `-h halt`, `-u un-halt`, `-H halt+hold CPU`, `-K kick start APE` — all host-initiated.
- `apectl -q<DEC>   query specified PLDM Numeric Sensor ID` (L5839) and `-s<DEC>   query specified PLDM State Sensor ID` (L5848) — host issuing PLDM queries through APE. This **proves the management fw speaks PLDM**, which is the BMC-side query protocol DMTF-wise. The actual PLDM-over-NCSI sub-codes are not enumerated in this PDF.
- `apelog` (§10.70 onward, L5884+) — audit log and event log in NVRAM. Host can read; nothing about BMC-side write.
- `apetest -w   write the file apediag.bin to scratchpad only` (L10114) and `-l/-u   Load/Unload APE diagnostic firmware`, `-G<DEC>/-g<DEC>   Set/Clear APE GPIO output pin <0-6>` (L10110-10112) — host-side APE fw replacement and GPIO drive. **Notable:** `apetest -G/-g` lets the host wiggle the APE's GPIOs 0-6, which on the X11SSZ-class NIC are wired to the BMC: a sideband signaling primitive worth a follow-up. Unverified which GPIO maps where; doc does not say.

## Broadcom OEM NCSI sub-codes mentioned anywhere in the doc

**None.** Searched `0x113D`, `113d`, `IANA`, `MFG ID`, `Manufacturer ID`, `OEM command`, `vendor command`, `Broadcom OEM`, `NCSI OEM`, `sub-command`. Zero hits in the diagnostic guide.

The doc treats NCSI strictly as a *transport configuration* (RMII vs SMBus, package ID, slave addresses) and never enumerates wire-level command codes.

Companion-doc note: separate Broadcom NCSI OEM map exists in this repo at `docs/bcm5709-ncsi-oem-cmd-map.md` — not derived from this PDF.

## Things explicitly described as host-only — DO NOT chase from BMC

These are documented but their input path is PCIe BAR0 / DMA / host shell:

- `DMAW -K <hex>`, `DMAR -K <hex>` — host-DMA to absolute phys addrs.
- `C3 DMA Test`, `B5 MBUF SRAM DMA Test`, `dmatest`.
- `apectl`, `apeinfo`, `aperead`, `apeping`, `apeotpkey`, `apetest`, `apelog` — all entered at the host shell.
- `setipmi`, `setump`, `setasf`, `setmba`, `setpxe` — NVRAM feature-flag writers.
- `umpcfg`, `umpecho`, `asfcfg`, `mancfg`, `bmcfg`, `asfmbox`, `asfprg`, `asfeng` — NVRAM/management-fw configurators.
- `seprg`, `seread`, `sedump`, `seotp`, `flshmode`, `userblock`, `segencrc` — NVRAM image management.
- `regdump`, `inp`, `outp`, all `dump*` cmds — register/state inspection.
- `apeinfo -u`, `apeinfo -c`, `apeinfo -r`, `apeinfo -E`, `apeinfo -e`, `apeinfo -s1/s2`, `apeinfo -m`, `apeinfo -4/-6/-d`, `apeinfo -t`, `apeinfo -l`, `apeinfo -A`, `apeinfo -x`, `apeinfo -i` — host-side display/export only.

In short: **the entire 10.x command catalog is host-driven.** The PDF is the *host* diagnostic guide; the BMC-reachable surface lives in the IPMI/UMP/ASF/DASH fw images that this tool *programs into NVRAM and toggles on*.

## Open questions (1 sentence each, ordered by leverage)

1. **What is the actual NCSI OEM cmd surface the DASH/IPMI/UMP fw images expose once `setipmi -e` (etc.) is set?** — this PDF doesn't say; need the DASH/IPMI fw spec or RE of `dashfw.rom`.
2. **What `ss=source` values does `apectl -e dd ee ss` accept, and is one of them "sideband"?** — if a BMC-originated NCSI cmd can inject an APE event, that's the missing primitive; not documented here.
3. **Which APE GPIOs 0-6 (`apetest -G/-g`) are wired to BMC pins on the Supermicro X11-class boards we care about?** — board-specific, not in this guide.
4. **What does `apeotpkey -p Provision management controller` actually burn?** — the trust root for sideband auth, almost certainly, but the doc gives no field-level detail.
5. **What is in `bmcfg`'s `APE_CFG` record beyond cert + private key?** — `mancfg -W Replace web file and data records` hints at an embedded web-mgmt blob; worth a `mancfg -V` dump on a live NIC.
6. **Is there a runtime PLDM-over-NCSI cmd code map?** — `apectl -q/-s` proves APE answers PLDM Numeric/State sensor IDs; the wire encoding is not in this PDF.
7. **Does `umpecho` accept a remote echo from the BMC side without the host having toggled `-e`?** — UMP echo is plausibly always-on once UMP fw is loaded; doc only describes host-driven enablement.

## Verbatim quotes table (cmd → exact PDF text)

| Cmd | Line(s) | Verbatim |
|---|---|---|
| `apeinfo -n` | 5757 | `-n                  Show random#/NCSI` |
| `apeinfo -f` | 5753 | `-f                  Show receive management filters` |
| `apeinfo -u` | 5763 | `-u                  Show USB/UMP ctrl registers` |
| `apeinfo -C` | 5781 | `-C                  Export bmcfg buffer (scratchpad->file)` |
| `apectl -f` | 5809 | `-f<HEX>             turn rx mgmt filter all(-f2)/on(-f1)/off(-f0)` |
| `apectl -e` | 5815 | `-e<HEX>             send APE custom event ddeess (dd=data, ee=event id, ss=source)` |
| `apectl -q` | 5839 | `-q<DEC>             query specified PLDM Numeric Sensor ID` |
| `apectl -s` | 5848 | `-s<DEC>             query specified PLDM State Sensor ID` |
| `apectl -A` | 5850 | `-A<DEC>             send ASF remote control request (rst:0, off:1, on:2, pwrRst:3)` |
| `apeping` | 5857-5858 | `Send APE event to ping host from APE. The host can be IPv4, IPv6 address or host name for a DNS lookup.` |
| `apeotpkey -p` | 5880 | `-p                  Provision management controller` |
| `apeotpkey -u` | 5882 | `-u                  Unprovision management controller` |
| `apetest -w` | 10114 | `-w               write the file apediag.bin to scratchpad only.` |
| `apetest -G/-g` | 10110-10112 | `-G<DEC>          Set APE GPIO output pin <0-6>` / `-g<DEC>          Clear APE GPIO output pin <0-6>` |
| `setipmi` | 9610-9621 | full block, see SETIPMI section above |
| `setump` | 9623-9634 | full block, see UMP section above |
| `setasf` | 5165-5185 | `Description: Enable/Disable ASF`, options `-d/-e/-q` |
| `umpcfg` | 9564-9598 | full sub-menu, see UMP section above |
| `umpecho` | 9532-9562 | full block, see UMP section above |
| `mancfg -C` | 4905 | `-C              Create self-signed server certificate and private key` |
| `mancfg -p` | 4931 | `-p               Export public key to DER encode file` |
| `mancfg -W` | 4927 | `-W               Replace web file and data records from cfg or ini file` |
| `seprg -a -b -k300` | 4644-4651 | `Program NVRAM with APE DASH firmware dashfw.rom as APE UPDATE image and pad up to 300kilo bytes. Padding and backup image is needed to enable out-of-band DASH` |
| NCSI cfg 60 | 3694-3698 | `NCSI pkg ID assign method (5718/5719/5720 only) ... GPIO (0) ... NVRAM (1)` |
| NCSI cfg 62 | 3706-3710 | `NCSI BMC connection method ... RMII (0) Through RMII / SMbus (1) Through SMbus` |
| NCSI cfg 63 | 3713-3717 | `NCSI SMbus Speed ... 100 (0) 100 KHz / 400 (1) 400 KHz` |
| NCSI cfg 64-65 | 3720-3727 | `NCSI NIC SMBus Slave Address` / `NCSI BMC SMbus Slave Address` |
| SMB addr 51-52 | 3162-3163 | `Pri. Port SMB Address (ASF/IPMI) : A4` / `Sec. Port SMB Address (IPMI) : A6` |
| Error codes | 10325-10339 | `ERR_UMPLB 156`, `ERR_UMPCTRL 157 Error: UMPCtrl 0x5F0 = XXXX`, `ERR_MISS_UMP 163`, `ERR_UMP_VS_DEV 169 UMP VS Device Error` |
