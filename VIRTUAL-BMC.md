# Virtual BMC (`zipmi vbmc`)

`zipmi.vbmc` is a minimal IPMI BMC server. It speaks IPMI 1.5 (LAN) and
2.0 (LAN+ / RMCP+) over UDP and answers a small core set of commands.
Useful as:

- a CI fixture (zipmi's own tests + downstream consumers can target it
  without needing real BMC hardware)
- a fuzz target (`zipmi fuzz sweep`, RAKP mutation, length corruption)
- a controllable BMC stand-in when developing tooling

It is **not** a complete BMC. It models enough surface to look like a
real BMC for fingerprinting and protocol-level exercises, no more.

## Quickstart

Run a vbmc on loopback:

```bash
zipmi vbmc serve --persona generic --port 6230
# → vbmc generic listening on 127.0.0.1:6230
```

Talk to it from another zipmi (or ipmitool):

```bash
zipmi -H 127.0.0.1 -p 6230 -U root -P "" mc info
zipmi -H 127.0.0.1 -p 6230 -U root -P "" chassis status
ipmitool -I lanplus -H 127.0.0.1 -p 6230 -U root -P "" mc info
```

Trace what the vbmc receives and sends:

```bash
zipmi -v vbmc serve --port 6230      # event log per packet
zipmi -d vbmc serve --port 6230      # event log + hex dump
```

Example `-v` output:

```
vbmc generic listening on 127.0.0.1:6230
  [13:18:14.665] ← recv  38B  Get Session Challenge       from 127.0.0.1:53773
  [13:18:14.665] → send  42B  Get Session Challenge       to   127.0.0.1:53773
  [13:18:14.665] ← recv  59B  Activate Session            from 127.0.0.1:53773
  [13:18:14.666] → send  32B  Activate Session            to   127.0.0.1:53773
  ...
```

## Personas

The persona selects the identity bytes the vbmc reports (vendor IANA,
product ID, firmware revision, GUIDs, default credentials).

| Persona       | Manufacturer | Product | FW   | Default user / pass |
|---------------|--------------|---------|------|---------------------|
| `generic`     | 0 (none)     | 0x0001  | 0.0  | `root` / *(empty)*  |
| `dell_idrac6` | 674 (Dell)   | 0x0100  | 1.70 | `root` / `calvin`   |

Source: `zipmi/vbmc/personas/`. New personas are a single Python file
returning a `Persona` dataclass — copy `generic.py` and edit the fields.

## Implemented commands

Wire-level handlers live in `zipmi/vbmc/handlers.py` (dispatch table) and
`zipmi/vbmc/server.py` (session management).

### Application (NetFn 0x06)

| Cmd  | Name                          | Notes                          |
|------|-------------------------------|--------------------------------|
| 0x01 | Get Device ID                 | Returns persona's identity     |
| 0x04 | Get Self Test Results        | Always 0x55 (no errors)        |
| 0x08 | Get Device GUID               | Persona's `device_guid`        |
| 0x37 | Get System GUID               | Persona's `system_guid`        |
| 0x38 | Get Channel Auth Capabilities| Reports auth types supported   |
| 0x39 | Get Session Challenge         | Issues temp session ID         |
| 0x3A | Activate Session              | Validates challenge, opens 1.5 |
| 0x3B | Set Session Privilege Level   | Grants requested priv          |
| 0x3C | Close Session                 | Drops session state            |

### Chassis (NetFn 0x00)

| Cmd  | Name              | Notes                                |
|------|-------------------|--------------------------------------|
| 0x01 | Get Chassis Status| Reports persona's power-on state     |
| 0x02 | Chassis Control   | Accepts on/off/cycle/reset (no-op)   |

### Storage / SEL (NetFn 0x0A)

| Cmd  | Name              | Notes                                |
|------|-------------------|--------------------------------------|
| 0x40 | Get SEL Info      | Reports default SEL entry count      |
| 0x42 | Reserve SEL       | Issues reservation token             |
| 0x43 | Get SEL Entry     | Returns persona's seeded entries     |

### IPMI 2.0 / RMCP+

The vbmc terminates the full RMCP+ handshake:

- Open Session
- RAKP1 → RAKP2
- RAKP3 → RAKP4

Once activated, any in-session command in the dispatch table above is
answered the same way as 1.5. Cipher suite 3 (HMAC-SHA1 + AES-CBC-128)
is the only suite implemented end-to-end.

### ASF (RMCP class 6)

- Presence Ping → Presence Pong (responds with persona's IANA + supported
  entities = IPMI + ASF v1.0)

### Everything else

Any (NetFn, cmd) tuple not in the table returns completion code
`0xC1` (Invalid Command). The vbmc never drops a packet silently —
either it replies, or it crashes loud (trace will show it).

## State model

`zipmi/vbmc/state.py` holds the mutable bits:

- `chassis_on` — toggled by Chassis Control
- `sel_entries` — list of SEL records (seeded from
  `default_sel_entries()` at startup)
- `sessions_15`, `sessions_20` — active session table keyed by session ID
- `sel_reservation_id` — incrementing reservation token

State is in-process only. Restarting the vbmc resets everything.

## Trace flags

`-v` / `-d` work both at the top level (`zipmi -v vbmc serve …`) and on
the subverb (`zipmi vbmc serve -v …`):

- **`-v` / `--verbose`** — print one timestamped event line per inbound
  and outbound UDP datagram, with the parsed NetFn/cmd name and the peer
  `address:port`.
- **`-d` / `--debug`** — everything `-v` shows, plus a hex dump of every
  packet (inbound `← RECV`, outbound `→ SEND`).

## Limitations

- No real SDR repository (commands not implemented).
- No real sensors — readings if added would be persona-defined static
  values.
- No IPMB bridging (Send Message / channel-bridged commands).
- No FRU storage.
- No user/channel configuration commands (Set User Access, Set Channel
  Access etc.) — they return 0xC1.
- Only cipher suite 3 for RMCP+. The dispatcher accepts Open Session
  requests for other suites but RAKP4 will fail.
- One client at a time is the tested path; concurrent sessions are not
  guarded against.

## Source layout

```
zipmi/vbmc/
  server.py        — asyncio UDP loop, session handshake, dispatch
  handlers.py      — per-command response builders + DISPATCH table
  state.py         — Persona + mutable session/SEL state
  personas/
    generic.py
    dell_idrac6.py
```

See also: `README.md` (top-level), `docs/ipmi-notes.md`.
