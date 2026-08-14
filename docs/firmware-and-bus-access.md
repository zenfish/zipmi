# Firmware & bus access over IPMI — what zipmi can (and can't) reach

IPMI is a management protocol, not a bus transport. It does not speak SPI or
eSPI. This note maps what buses/firmware you can actually touch through zipmi.

## Bus reachability

| Bus | Reachable over IPMI? | zipmi | Notes |
|-----|:--------------------:|-------|-------|
| **I2C / SMBus** | ✅ | `i2c`, `i2cscan`, `i2c-id`, `spd` | Master Write-Read (App 0x06/0x52). Reaches SPD EEPROMs, sensors, PMBus PSUs, backplane MCs on a BMC-mastered bus. |
| **SPI (raw)** | ❌ | — | IPMI defines no SPI transport. No command speaks SPI over UDP/623. |
| **eSPI** (host↔BMC) | ❌ | — | Hardware bus (LPC successor) between chipset and BMC. Physical / JTAG only — not an IPMI surface. |
| **SPI *flash contents*** | ⚠️ indirect | vendor OEM dump cmds | The BMC reads its **own** SPI/MTD flash for you via a vendor OEM command; you never speak SPI yourself. |

**Bottom line:** you cannot *speak* SPI or eSPI over IPMI with any tool. zipmi
gives you (a) an I2C/SMBus master via Master Write-Read, and (b) the vendor OEM
firmware-dump path where the BMC `dd`s its own flash and streams it back.

## Supermicro firmware dump — `oem supermicro fwdump`

Supermicro X10–X13 (ASPEED AST2300/2400, the smcipmi/ATEN stack) expose an
AlUpdate firmware-dump family under **NetFn 0x3e**:

| Cmd | Name | Effect |
|-----|------|--------|
| `0x1d` | FwDumpStart | BMC runs `dd if=/dev/mtdblockN` (whole flash, "all_part") → `/tmp/dump_flash` |
| `0x1e` | FwDumpStatus | Poll; returns `0x01` + 24-bit big-endian size when ready |
| `0x1f` | FwDumpRead | Streams the dump in 55-byte chunks |

`zipmi oem supermicro fwdump [outfile]` orchestrates the whole sequence —
start → poll size → read 55-byte chunks until the reported size is drained →
reassemble to `outfile` (default `flash.bin`). Honors `--json` (emits
`{reported_size, bytes_read, out, ok}`).

```
zipmi -I lanplus -H <bmc> -U ADMIN -P ADMIN oem supermicro fwdump flash.bin
# where the box permits cipher-0, it is reachable pre-auth (auth-only RMCP+,
# 0x00 confidentiality/integrity) — see `scan cipher-zero`.
```

The dumped image is the full flash: base OS, web UI, BMC config, kernel, and
often password files and SSH keys. Vendor-supported behavior (no CVE).

**Scope / testing:** X10–X13 only. X14 is OpenBMC and lacks it — `fwdump`
returns a clean `0xc1` ("not an ATEN/X10-X13 BMC?"). The command is
encoding- and orchestration-unit-tested; functional verification needs a real
X10–X13 target (the vBMC zoo has none).

Reference: the command names + per-command RE context live in
`zipmi/scapy_ipmi/oem/supermicro.py` and `supermicro_known_context.py`
(smcipmi RE + SMCIPMITool decompile). Public writeup of the technique:
<https://trouble.org/remotely-access-supermicro-firmware/>.

## Other vendors

Dell iDRAC references an on-BMC SPI shadow (`/mmc1/SPI_shadow.bin`) in several
0x30/0x2e handlers (see `oem/idrac10_commands_generated.py`) — used as a guard on
factory-reset / LC-wipe paths, not a dump primitive. No turnkey Dell flash-dump
verb exists in zipmi yet.
