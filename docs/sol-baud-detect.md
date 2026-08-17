# SOL bit-rate detection (`zipmi sol info`)

**Status:** implemented 2026-05-23 (spec written same day). Shipped as the
`zipmi sol` verb — `sol info`/`sol baud` cover the bit-rate detection below;
`sol activate`/`deactivate`/`looptest`/`set`/`payload` add the full
`ipmitool sol` surface (RMCP+ payload type 1). Live-verified vs Dell iDRAC6
192.168.0.23 (volatile bit rate 19.2 kbps = 19200, matching `ipmitool sol
info`). See `zipmi/sol.py`, `zipmi/cli/zipmi.py`, `examples/03_sol_info.py`.

**Important caveat — config readout vs the actual wire.** `sol info`/`sol
baud` (like `ipmitool sol info`) report the BMC's *configured* rate. They
CANNOT detect a host whose UART physically runs at a different rate — the
classic cause of a garbled `sol activate`. On 192.168.0.23 the BMC was
configured for 19200 but the host serial was actually **57600**, so the
console was pure garbage. For that, `zipmi sol autobaud` retunes the BMC's
volatile rate to each candidate (115200/57600/38400/19200/9600), samples
the live host output, scores printable-ASCII ratio, and applies the rate
that yields clean text — a host-side detector that neither ipmitool nor
`sol baud` provides. Verified: autobaud picked 57600 (100% printable;
19200 scored 0%), after which `sol activate` showed the real `Password:`
prompt.

## Why

Booting a host over PXE/serial requires the kernel `console=ttyS1,<baud>` to match
the BMC's Serial-Over-LAN bit rate, or all post-BIOS console output is garbage and
the boot is effectively blind. BMC SOL defaults vary widely:

| BMC | Typical SOL default |
|-----|---------------------|
| Dell iDRAC6 | **19200** (verified on 192.168.0.23, FW 1.70) |
| Dell iDRAC7+/9 | 115200 |
| Supermicro / most others | 115200 (sometimes 57600) |

In the BMC→PXE pivot PoC (author's BMC→PXE pivot PoC), guessing 57600
then 115200 cost two blind boot cycles before `ipmitool sol info` revealed 19200.
We want zipmi to read this so a tool can set the right console baud automatically.

## What ipmitool does

`ipmitool sol info` issues **Get SOL Configuration Parameters** repeatedly, one
parameter selector at a time, and decodes the responses. We only need the bit-rate
params for baud detection; the rest (enable, auth, thresholds) are nice-to-have for
a full `sol info` clone.

## IPMI command details

**Get SOL Configuration Parameters** — NetFn = Transport (`0x0C`), Cmd = `0x22`.

Request bytes:
| Byte | Meaning |
|------|---------|
| 1 | bits[3:0] = channel number; bit[7] = 1 → "get parameter revision only" (use 0) |
| 2 | parameter selector (see table) |
| 3 | set selector (0x00 unless the param is a set) |
| 4 | block selector (0x00 unless block-addressed) |

Response bytes:
| Byte | Meaning |
|------|---------|
| 1 | completion code |
| 2 | parameter revision |
| 3.. | parameter data |

Relevant parameter selectors (IPMI 2.0, §26 SOL Configuration Parameters):
| Selector | Name | Data |
|----------|------|------|
| 5 | SOL **non-volatile** bit rate | 1 byte, bits[3:0] = bit-rate code |
| 6 | SOL **volatile** bit rate | 1 byte, bits[3:0] = bit-rate code |
| 1 | SOL enable | 1 byte, bit[0] = enabled |
| 8 | SOL payload port | 2 bytes LSB-first (usually 623) |

Use **selector 6 (volatile)** as the live rate; fall back to 5 if 6 reads 0.

Bit-rate code → baud (bits[3:0] of the data byte):
| Code | Baud |
|------|------|
| 0x06 | 9600 |
| 0x07 | **19200** |
| 0x08 | 38400 |
| 0x09 | 57600 |
| 0x0A | 115200 |

iDRAC6 returns `0x07` → 19200, matching `ipmitool`'s "Volatile Bit Rate (kbps): 19.2".
(Verify the full code table against the IPMI 2.0 spec table when implementing;
above covers every value seen in the lab.)

Channel number: SOL rides the LAN channel. Pass the same channel zipmi already uses
for lanplus (commonly 1; on some Dell it is the "current channel" 0x0E). Try the
session's active channel, then 0x0E.

## Where to add it in zipmi

Follow the existing sessionless/RAKP request pattern used by `bmc-id`:
- Command encode/decode → `zipmi/scapy_ipmi/commands.py` (add
  `get_sol_config_param(channel, selector, set_sel=0, block=0)` returning raw data,
  plus a `sol_bit_rate(channel)` helper that reads selector 6, masks `& 0x0F`,
  maps via the table above, returns int baud or None).
- Reuse the Transport NetFn constant; add `0x22` cmd name to
  `zipmi/scapy_ipmi/cmd_names.py` if not present.
- CLI subcommand → `zipmi/cli/zipmi.py`: add `sol info` (full dump) and a thin
  `sol baud` that prints just the integer (script-friendly).
- Example → `examples/03_sol_info.py` mirroring `examples/02_get_device_id.py`.

### Function sketch
```python
SOL_BITRATE = {0x06: 9600, 0x07: 19200, 0x08: 38400, 0x09: 57600, 0x0A: 115200}

def sol_bit_rate(session, channel=None):
    """Return live SOL baud (int) or None. Reads volatile param (6), falls back to 5."""
    for sel in (6, 5):
        data = get_sol_config_param(session, channel, selector=sel)  # NetFn 0x0C cmd 0x22
        if data:                       # data[0] is the bitrate byte (after param-rev)
            code = data[0] & 0x0F
            baud = SOL_BITRATE.get(code)
            if baud:
                return baud
    return None
```

## Test plan
- iDRAC6 `192.168.0.23` root/calvin → expect **19200** (ground truth).
- iDRAC9 / Supermicro `192.168.0.24` (AST2400) → compare against `ipmitool sol info`.
- Cross-check every target: `ipmitool -I lanplus -H <ip> -U <u> -P <p> sol info`
  "Volatile Bit Rate" must equal `zipmi sol baud`.

## Downstream consumer
`pwn.sh` (BMC→PXE pivot PoC) should call `zipmi sol baud <bmc>` and template the
pxelinux `console=ttyS1,<baud>n8` instead of hardcoding. See the PoC's todo.md
"SOL baud auto-detect" item. Related: `BMC-ID.md`, `docs/ipmi20-rakp.md`.
