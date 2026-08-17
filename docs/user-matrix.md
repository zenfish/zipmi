# `zipmi user-matrix` — reading the grid

`user-matrix list` enumerates the **full user × channel privilege/auth/cipher
grid** in one session — the picture `ipmitool` and friends don't give you.
Because it surfaces the whole IPMI channel model, some of what it shows is
**non-standard territory**. This is how to read it.

```
zipmi -H <bmc> -U <user> -P <pass> user-matrix list
zipmi -H <bmc> ... user-matrix list --json | jq .        # machine-readable
zipmi -H <bmc> ... user-matrix list --findings           # + posture flags
```

## The header

```
target 1.220.94.173  users 4/16
```

- **target** — the BMC you queried.
- **users X/Y** — `enabled_user_count / max_user_count`, from Get User Access
  (user 1). Y is how many user-ID slots the BMC has; X is how many are enabled.
  Discovery runs on `0xE` (the channel your session is on) — sessionless
  channels like IPMB/KCS reject the query, so leading with channel 0 would
  wrongly report `0/0`.

## The channel lines

```
ch0:  IPMB (I2C)                    / sessionless    / limit=?
ch1:  802.3 LAN                     / multi-session  / limit=administrator
ch2:  asynch serial/modem          / single-session / limit=administrator
ch3:  system interface (KCS/…)     / sessionless    / limit=?
ch15: system interface (KCS/…)     / sessionless    / limit=?
```

Each line is `chN: <medium> / <session-support> / limit=<ceiling>` from
`Get Channel Info (0x42)` + `Get Channel Access (0x41)`.

### medium
The physical/logical transport: IPMB (I2C), 802.3 LAN, async serial/modem, PCI
SMBus, SMBus, system interface (KCS/SMIC/BT), USB, OEM. See the protocol
writeup: the author's IPMI channels/users/auth research doc (private).

### session-support
- **multi-session** — several sessions at once (LAN). A new connection gets its
  own slot.
- **single-session** — **one** session slot (typical serial/modem). A second
  connection while one is active is **refused** — it does **not** kick or
  interrupt the first. One line, one caller.
- **sessionless** — no login at all (IPMB, KCS/system-interface). Trust is
  physical/local, not credential — there is nothing to authenticate against.

### limit = the channel privilege *ceiling*
`limit` is the **channel privilege limit** (`Get Channel Access 0x41`, byte 3):
the cap on privilege for **any** session on that channel, **independent of the
user**. This is the second of the two stacking ceilings — it can override even a
user whose own record says Administrator:

- `limit=administrator` → sessions may negotiate up to Admin.
- `limit=operator` → **everyone**, including an admin user, is capped at
  Operator on that channel.
- `limit=?` → we could not read it. `0x41` erred on that channel — sessionless
  internal channels (IPMB, KCS) often have no LAN-style access record. `?` means
  *unreadable*, not zero.

Effective session privilege = `min(requested, user's per-channel limit, channel
limit, cipher-suite privilege)`.

## The cells

```
user              ch1              ch2
 2 root           administrator E la   operator la
```

Each cell = `<priv> <flags>` from `Get User Access (0x44)` for that
(user, channel):
- **priv** — this user's max privilege limit on this channel.
- **E** — IPMI messaging enabled · **la** — link-auth enabled · **ci** — callin
  (restricted-to-callback).
- **`err:0xNN`** — the query failed for that cell (e.g. IPMB/KCS rejecting Get
  User Access). Non-fatal; the rest of the grid still completes.

## The `Δ` (delta) notes

```
Δ ch1: priv_limit present=operator non-volatile=administrator (pending/override)
```

`Get Channel Access` has **two** stored copies — **present (volatile)**, active
now, and **non-volatile**, applied at next boot. When they differ it is a
finding: either a **pending downgrade** (NV lowered, reboot will drop it) or a
**runtime override** (volatile restricted, reboot restores it). `user-matrix`
reports the present value and flags the delta. (This split exists only on
channel access, not user access.)

## `--findings` (posture flags, derived, off by default)

Passive flags computed from the collected data (no extra packets): cipher-0
advertised, anonymous/null login enabled, `auth type 'none'` offered,
per-message-auth or user-level-auth disabled. `scan all` runs the grid with
findings **on**.

## Same medium, different channels — are they the same wire?

Two channels of the same medium (e.g. **ch1 and ch9 both 802.3 LAN**) are
**distinct logical channels**, independently configured (own auth, ciphers,
privilege limit) — **separate security surfaces** regardless of wiring. On many
platforms (e.g. IBM IMM2) that is a **dedicated management NIC vs a shared/host
LOM sideband** — often different physical ports, sometimes one NIC exposed
twice. To tell them apart, read each channel's `Get LAN Config (0x02)`: a
different MAC = a different NIC.

Multiple **system-interface (KCS/BT)** channels (ch3/4/8/15) are the
**host↔BMC in-band** paths — not remote wires. `0xF` is the canonical one; the
others are extra in-band channels (different KCS/BT instances or LUNs). Same
physical route (host LPC/eSPI to the BMC), different logical channels. Only the
host OS (`/dev/ipmi0`) touches them; they are **not remotely reachable**.

## The default / connected channel

IPMI has no "set default channel" command. `0xE` = "the channel this request
arrived on" is the contextual default. Your remote session lands on whatever LAN
channel `-H` reached; the host's default is the system interface. `user-matrix`
resolves `Get Channel Info(0xE)` and **marks the channel your session is on**:

```
ch1: 802.3 LAN / multi-session / limit=administrator  ← connected
```

(`"connected": true` on that channel in JSON.) Note: ipmitool/freeipmi don't
hardcode a channel either — they **discover** the first LAN channel by walking
`Get Channel Info` for `medium == 802.3 LAN` (ipmitool's `find_lan_channel`,
searching from channel 1 up), and use `0xE` for "current channel" elsewhere.

## `--medium` — as much about the substrate as we can query

Get Channel Info gives the medium *type*; `--medium` pulls the medium-specific
config, the analog of `Get LAN Config` for each wire:

```
zipmi -H <bmc> ... user-matrix list --medium
  ch1: 802.3 LAN / multi-session / limit=administrator  ← connected
        └ mac=aa:bb:cc:dd:ee:ff  ip=10.0.0.5/static  vlan=100
  ch9: 802.3 LAN / multi-session / limit=administrator
        └ mac=aa:bb:cc:dd:ee:00  ip=10.0.1.5/static
  ch2: asynch serial/modem / single-session / limit=administrator
        └ mode=ppp modem
```

- **LAN** (`Get LAN Config 0x0C/0x02`): MAC (param 5), IP (3), IP source (4),
  VLAN (20). **Different MAC on ch1 vs ch9 = genuinely different NICs**; same MAC
  = one NIC exposed as two channels. This is how you answer the "same wire?"
  question.
- **Serial/modem** (`Get Serial/Modem Config 0x0C/0x11`): `--medium` sweeps
  **every** param — connection mode, **modem init/dial strings** (ASCII-decoded,
  so you see the actual `ATDT…` and phone numbers), callback control, alert
  destinations. `zipmi serial config [chan]` dumps them standalone. IPMI has no
  direct "is a modem physically plugged in" query — a dial string configured
  means the channel is *set up* to dial; physical presence is inferred from
  config + carrier. **Dial-out surface:** `zipmi serial set <chan> <param> <hex>`
  (admin, `--yes`) writes those params — e.g. a destination dial number or the
  raw modem AT init string. With a matching PEF alert (or callback) that makes
  the BMC **dial an arbitrary number** — callback hijack / war-dial / PSTN pivot.
  Full PoC is research task `26-08-10-e`.
- **System interface** (`Get System Interface Capabilities 0x06/0x57`): KCS/BT
  transaction capabilities (raw for now).

Unreadable params are omitted, not guessed.

## Talking to a channel you are not on — bridging

The IPMB (and other non-LAN channels) are not remotely reachable directly. Two
ways to reach them:

1. **Bridge from your LAN session** via `Send Message (0x34)`: the BMC
   de-encapsulates your request and routes it onto the target channel (e.g. the
   IPMB, to a PSU/HSC satellite controller). You are authed on LAN; the bridged
   frame rides out **unauthenticated** on the internal bus.
2. **Be a node on the bus** — physically attach to the IPMB and speak to the
   BMC's slave address `0x20`, no auth.

Whether the BMC *permits* bridging (and to which channels) is enumerable with
`--bridge`:

```
zipmi -H <bmc> ... user-matrix list --bridge
  ch0:  IPMB (I2C) / sessionless / limit=?  bridge:yes
  ch1:  802.3 LAN / multi-session / limit=administrator  bridge:no  ← connected
```

**How the probe works:** for each channel it issues `Send Message (0x34)`
wrapping a benign `Get Device ID` (App `0x06/0x01`) — the request is
IPMB-encapsulated (rsSA / netFn / checksum / rqSA / seq / cmd / checksum) and the
channel/tracking byte selects the target. The completion code tells you:
`0x00` = **bridge accepted** (`bridge:yes`), `0xC1` = Send Message unsupported,
any other cc = permitted-but-rejected-for-this-channel. (JSON carries
`{"bridge": {"supported", "bridgeable", "cc", "detail"}}` per channel.)

Bridgeable channels are **reach edges** — `user-matrix list --json --bridge`
(with `--medium` for the MACs/IPs) is the connectivity source that feeds a
hardware-connectivity graph. A converter that turns this JSON into that graph
is part of the author's private research toolchain (not shipped here); it emits
`BMC → CHn` per channel, `CHn(LAN) → LAN` (external reach, labelled with
MAC/IP), and — the payoff — `<connected-channel> → CHn` for every `bridge:yes`
channel (internal reach: which buses your LAN session can pivot onto via Send
Message).

## Relation to the protocol writeup

The *why* behind all of this — global-identity/per-channel-access, the two
ceilings, the auth-by-medium model, the internal injection surface — is in
the author's IPMI channels/users/auth research doc (private; doc-UUID
`bffab790-2ab1-4e3b-8eaa-25e7163b4a2f`). This file is the operator's guide to the
tool output; that one is the protocol/security model.
