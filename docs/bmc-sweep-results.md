# BMC sweep results — `scripts/ipmi_sweep.py`

Authenticated, read-only run of `scripts/ipmi_sweep.py` against every BMC in the
lab "zoo" (the qemu virtual-BMC fleet). Each run opens one RMCP+ session and
fires the **107 read-only** commands from `IPMI_CMD_NAMES`; the 81 write/
side-effect commands are skipped by default (`--danger` to include them).
Counts below are over those 107.

Swept 2026-08-12.

| Box | Vendor / SoC | Mfr ID | FW | Cipher | ok | unsup | cc_err | no_resp | other |
|-----|--------------|-------:|----|-------:|---:|------:|-------:|--------:|-------|
| **idrac9** | Dell iDRAC9 / NPCM750 | 674 | 3.00 | 17 | 18 | 46 | 43 | 0 | — |
| **idrac10** | Dell iDRAC10 / NPCM845 | 674 | 0.00 | 3 | 16 | 45 | 46 | 0 | — |
| **supermicro-x14** | Supermicro X14 / AST2600 | — | — | 3 | 8 | 55 | 32 | 10 | 1 priv, 1 err¹ |
| **nvidia-obmc** | NVIDIA GB200NVL / AST2600 | 5703 | 3.01 | 17 | 13 | 59 | 28 | 7 | — |
| **openbmc** | Vanilla OpenBMC / AST2600 | 0 | 3.01 | 17 | 17 | 60 | 26 | 4 | — |
| **megarac-hpe** | HPE Cray XD670 (AMI MegaRAC) / AST2600 | 15370 | 0.00 | 3 | 23 | 35 | 44 | 0 | 5 priv |

Legend: **ok** = cc 0x00; **unsup** = cc 0xC1 (command not registered);
**cc_err** = any other non-zero completion code (bad param, needs data, etc.);
**no_resp** = timeout / empty reply; **priv** = cc 0xD4 (insufficient privilege);
**err** = transport/decode exception on that one command.

¹ supermicro-x14 returns `0xff` to Get Device ID (0x06,0x01) — a known qemu
persona quirk — so its Mfr ID / FW can't be read over IPMI; SoC is an AST2600.

## Notes

- **Cipher differs by box.** iDRAC9, NVIDIA and vanilla OpenBMC negotiate only
  **cipher 17** (HMAC-SHA256); iDRAC10, Supermicro X14 and MegaRAC take
  **cipher 3**. `ipmi_sweep` uses `--cipher 3` by default; pass `--cipher 17`
  for the SHA256-only boxes. A wrong cipher now fails cleanly
  (`# session failed: IPMIError: Open Session: status 0x04`), not with a
  traceback.
- **`ok`/`unsup` spread is the per-firmware fingerprint.** MegaRAC answers the
  most standard read commands (23); the minimal AST2600 personas answer fewer
  and mark more `unsupported`. Re-running after a zipmi change and diffing the
  golden JSON catches regressions in what we send or decode.
- **Framing map** (`--sessionless`) is a separate mode: it sends each command in
  both IPMI 1.5 and RMCP+ framing and flags `framing_asymmetric` when a BMC
  answers one wrapper but times out the other — the iDRAC10 signature that
  motivated the Get Channel Cipher Suites fix (0x54 over RMCP+, not 1.5).

## Reproduce

Golden captures live in `tests/golden/zoo/<box>.json`. To regenerate:

```bash
# Dell (raw Kuid key, -K)
python3 scripts/ipmi_sweep.py --host idrac9  --user root -K 915f...414af --cipher 17 --label idrac9  --out tests/golden/zoo/idrac9.json
python3 scripts/ipmi_sweep.py --host idrac10 --user root -K 915f...414af --cipher 3  --label idrac10 --out tests/golden/zoo/idrac10.json
# Supermicro X14 (password)
python3 scripts/ipmi_sweep.py --host supermicro-x14 --user ADMIN --password ADMIN --cipher 3 --label supermicro-x14 --out tests/golden/zoo/supermicro-x14.json
# NVIDIA / vanilla OpenBMC (cipher 17)
python3 scripts/ipmi_sweep.py --host nvidia-obmc --user root --password 0penBmc --cipher 17 --label nvidia-obmc --out tests/golden/zoo/nvidia-obmc.json
python3 scripts/ipmi_sweep.py --host openbmc     --user root --password 0penBmc --cipher 17 --label openbmc     --out tests/golden/zoo/openbmc.json
# HPE Cray / AMI MegaRAC (127.0.0.1:5623)
python3 scripts/ipmi_sweep.py --host 127.0.0.1 --port 5623 --user admin --password superuser --cipher 3 --label megarac-hpe --out tests/golden/zoo/megarac-hpe.json
```

Boxes are started with `vbmc <box> start` (fleet: `vbmc list`).

## Sessionless framing map (`--sessionless --framing both`)

Each command sent pre-auth in **both** IPMI 1.5 and RMCP+ framing; a command is
`framing_asymmetric` when it answers one wrapper but is silently dropped by the
other. Empty-body baseline, so a supported command replies `0xC7` (data length)
rather than `0x00` — the signal here is **answer vs. timeout**, not the code.

Only a handful of commands are reachable before a session exists; the
interesting one is **Get Channel Cipher Suites (0x54)**, an IPMI 2.0 command:

| Box | 0x54 via IPMI 1.5 | 0x54 via RMCP+ | asymmetric |
|-----|-------------------|----------------|:----------:|
| **idrac9**  | timeout | 0xC7 (answers) | **YES** |
| **idrac10** | timeout | 0xC7 (answers) | **YES** |
| supermicro-x14 | 0xC7 | 0xC7 | no |
| nvidia-obmc | 0xC7 | 0xC7 | no |
| openbmc | 0xC7 | 0xC7 | no |
| megarac-hpe | 0xC7 | 0xC7 | no |

**Takeaway:** the Dell iDRAC BMCs answer the IPMI 2.0 command **only over
RMCP+**; the OpenBMC/AMI-MegaRAC family answer over either wrapper. This is
exactly why `scan cipher-suites` had to send 0x54 over RMCP+ — and it is *not*
iDRAC10-specific: iDRAC9 drops the 1.5-framed probe just the same (it was only
ever reported on iDRAC10). Sessionless captures: `tests/golden/zoo/sessionless/`.

Pre-auth reachable set also differs by vendor: Dell answers System GUID + Auth
Caps + 0x54; the OpenBMC family answers Auth Caps + Payload status + 0x54;
MegaRAC additionally answers Get Session Challenge. Everything else times out
pre-auth (`retries=0` keeps the sweep fast).

## Bridging privilege-escalation probe (`bridging privesc`)

Does Send Message bridging let a **capped-privilege session run an admin
command it can't run directly**? The BMC checks privilege on the *outer* Send
Message (0x34) — often only Operator — but may fail to re-apply the session's
privilege cap to the *bridged inner* command. That is an **incomplete-mediation**
bug (Saltzer & Schroeder 1975: privilege must be checked on *every* path to the
object), not anything IPMI-specific in the literature; privilege escalation as a
class long predates the "confused deputy" naming (Hardy 1988, capability
systems — analogous, unrelated to BMCs).

The probe caps the session with `--max-priv operator`, then:

1. requests Administrator via **Set Session Privilege Level (0x06/0x3B)**
   *directly* — a capped session is refused (`0x80` "level not available for
   this user", `0x81` "exceeds Channel/User privilege limit", or clamped);
2. **bridges the same request** to each present channel. Direct refused **and**
   bridged far cc `0x00` = the cap didn't follow the hop → escalation.

| Box | vendor | direct baseline | bridged escalation |
|-----|--------|-----------------|:------------------:|
| idrac9  | Dell | REFUSED `0x80` | none |
| idrac10 | Dell | REFUSED `0x80` | none |
| supermicro-x14 | Supermicro | REFUSED `0x81` | none |
| openbmc | OpenBMC (AST2600) | REFUSED `0x81` | none |
| megarac-hpe | AMI/HPE MegaRAC | REFUSED `0x81` | none |
| nvidia-obmc | NVIDIA GB200NVL OpenBMC | _pending_ | _pending_ |

**Takeaway:** every reachable box correctly caps the operator session *and*
refuses the bridged admin request — **none vulnerable, zero false positives**
across 4 vendors. The `--max-priv` cap (RAKP requested-role byte derived from
the priv nibble) holds cross-vendor: the direct baseline flips
`GRANTED admin → REFUSED` when capped, which is what makes the bridged
comparison meaningful. A negative result, but it exercises the probe end to end.

### Reproduce

```
# needs an account whose session can be capped below admin; --max-priv does the cap
zipmi -H idrac10 -U root -K <kuid-hex> --max-priv operator bridging privesc all
zipmi -H supermicro-x14 -U ADMIN -P ADMIN -C 3 --max-priv operator bridging privesc all --json
```

`escalation_found: true` in the JSON (or `*** ESCALATED ***` in text) is the
finding to chase. `--json` emits per-channel edges for the hardware-reach map.
