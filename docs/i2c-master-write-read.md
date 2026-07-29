# I2C over IPMI — `i2c` / `i2cscan` / `i2c-id`

Talk to I2C devices on a BMC's private buses **remotely, over LAN**, via IPMI
**Master Write-Read** (App NetFn `0x06`, Cmd `0x52`). The BMC firmware performs each
transaction, so this works even when the BMC exposes no `/dev/i2c-*` and ships no
`i2cdetect`/`i2cget` (e.g. Dell iDRAC6, which owns I2C through the proprietary
`aess_i2cdrv` char device). Commands live in `zipmi/cli/zipmi.py`.

## Commands

```sh
# single transaction — write reg pointer, read N (the primitive)
zipmi -H <bmc> -U <u> -P <p> i2c bus=0 0x1a 1 0x00

# sweep a bus in ONE session (i2cdetect-style)
zipmi -H <bmc> -U <u> -P <p> i2cscan bus=0            # --lo/--hi to bound (default 0x03..0x77)

# fingerprint one device — probe std MfrID/DevID/PMBus ID regs + 16-byte dump
zipmi -H <bmc> -U <u> -P <p> i2c-id bus=0 0x1a
```

- Addresses are **7-bit** (shifted for the wire internally).
- `bus=N` = private bus N; `bus=public [chan=N]` = public bus. Bus byte per IPMI 2.0 §22.11.
- Read-only: a "read" writes only the register-pointer byte. `i2c` takes extra write bytes if you need them.
- **Remote-enablement:** works iff the BMC allows Cmd `0x52` on the LAN channel at your
  privilege. Some BMCs restrict MWR to the system interface (KCS) or Admin. A blocked
  channel returns a non-zero completion code (a sweep that finds zero devices is the tell).

## Why the sweep is built in (not a shell loop)

MWR is **one transaction per call** — there is no "scan" verb in IPMI, in `ipmitool`, or in
raw MWR. A sweep is always a client-side loop; the only question is *where* the loop runs.
`i2cscan` runs it inside **one authenticated session**. A shell loop
(`for a in …; do zipmi i2c … ; done`) re-establishes a whole IPMI session per address.

### Measured (Dell iDRAC6, fw 1.70, 117 addrs `0x03..0x77`, bus 0, 2026-07-29)

| Approach | Wall | Per addr | vs native | Repeats per address |
|---|---|---|---|---|
| `zipmi i2cscan` (one session) | **0.97 s** | 8.3 ms | 1× | nothing — one RAKP, then 117 MWR reads |
| `ipmitool i2c` loop | 14.5 s | 123 ms | 15× slower | C startup 10 ms + **RAKP session ~110 ms** + MWR |
| `zipmi i2c` loop | 61.5 s | 526 ms | 63× slower | **Python/Scapy import ~0.4 s** + RAKP + MWR |

Three takeaways:

1. **The dominant per-call cost is the RAKP session (~110 ms on this BMC), not the read.**
   Both loops re-auth per address; `i2cscan` opens one session and reuses it. That alone is
   why even ipmitool's tight C loop is 15× slower than native.
2. **The loop-vs-loop gap (14.5 vs 61.5 s) is the Scapy import** ipmitool doesn't pay
   (`import scapy.all` = 0.68 s; ipmitool cold-start = 0.010 s; ×117 ≈ the 47 s difference).
3. **ipmitool structurally can't amortize** — every invocation is a fresh session. The
   in-session sweep needs a library with a persistent session object; hence built into zipmi.

### Why it doesn't go faster than ~1 s

Native is now import-bound + BMC-latency-bound, not loop-bound. The residual splits ~50/50:

- **~0.46 s one-time** = Scapy import (~0.35 s) + the first RAKP session (~0.11 s), paid once.
- **~0.5 s** = 117 *serial* MWR round-trips at ~4.4 ms (RTT 0.9 ms measured; the rest is the
  200 MHz ARM926 servicing each I2C transaction + Scapy per-packet build/parse).

Levers to go further: drop Scapy for `struct.pack` on this path (~0.5 s → ~0.05 s startup);
pipeline the MWRs to overlap round-trips (bounded by the BMC's serial processing); scan a
narrower range. None help the loops — those are dominated by the session/import they repeat.

## Verified finding

`i2cscan bus=0` on the iDRAC6 found 6 devices: 3 undocumented sensor chips at 7-bit
`0x1A/0x1C/0x1D` (NAK all standard ID regs, not PMBus — unidentified mainboard front-ends)
and 3 FRU/VPD EEPROMs at `0x52/0x54/0x55`. Only bus 0 answered MWR over LAN, so the sweep is
not exhaustive of the physical plant.

*Companion (full writeup, styled): `~/phd/bmc/ipmi/I2C-OVER-IPMI-MWR.html`.*
