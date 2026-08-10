# Design: `zipmi user-matrix list` — full user × channel privilege/auth matrix

**Date:** 2026-08-10
**Status:** approved design, pre-implementation
**Lineage:** the modern successor to `~/bin/mega_chan.py` (zen, 2014) — that tool
spot-checked channel auth/cipher posture sessionlessly and by hand; this brings
the whole matrix (users + channels + access + auth + cipher) into zipmi with a
real session, scapy layers, and machine output.

## Problem

The stock `zipmi user list` (and every ipmitool-alike) shows a **flat** user
list against a **single** channel (`0xE`, the present one). But IPMI identity is
global while **access is per-channel**, gated by two stacking ceilings (per-user
`Get User Access`, per-channel `Get Channel Access`) plus per-channel auth/cipher
policy. A user can be Admin on channel 1 and Operator (or disabled) on channel 3;
a channel can cap everyone below what a user record says; a backdoor can hide in
one setting on one channel. The flat list cannot show any of this.

We want a command that enumerates the **whole grid** and emits it faithfully,
with JSON for downstream consumers (recon pipeline, hwmaps injection-surface
matrix, cross-box diffing).

Reference writeup: `~/phd/bmc/ipmi/ipmi-channels-users-auth.html`
(doc-UUID `bffab790-2ab1-4e3b-8eaa-25e7163b4a2f`).

## Goals

- **Information-first.** Report the complete, faithful matrix. No opinions in the
  core output.
- **JSON output** for machine consumption (raw + decoded on every field).
- **One session.** All queries run inside a single RMCP+/1.5 session, iterating
  (user × channel) — never a session per channel (cf. the in-session I2C-MWR
  sweep).
- **Read-only enumeration.** No writes. (The write twins already exist:
  `user priv` = Set User Access 0x43, etc.)

## Non-goals (this iteration)

- No matrix-driven **writes** ("set cell X to Operator"). Future; plumbing exists.
- No **firmware-firewall / per-command** dimension (the 160-command matrix
  mega_chan mused about). Future.
- No dual **1.5-vs-2.0** re-probe — use the negotiated session's version.
- Anomaly/backdoor **flagging is not baked in** — it is an optional derived layer
  (`--findings`), because "root differs across channels" is a *derivation* over
  the facts, and consumers (or a later `user-matrix diff`) can compute it.

## Command

```
zipmi user-matrix list [--json] [--all] [--per-priv] [--findings]
```

Global flags reused verbatim: `-H/-U/-P/-C/-I/-t` + env (`ZIPMI_TARGET/USER/PASS/CIPHER`).

| Flag | Effect |
|---|---|
| *(none)* | Human table (default). Populated channels only. |
| `--json` | Emit JSON to **stdout only** (status/errors to stderr). |
| `--all` | Include empty/unimplemented channel numbers as rows. |
| `--per-priv` | Sweep `Get Channel Auth Caps (0x38)` at all 5 privilege levels (default: single query at Administrator). Guards BMC DoS. |
| `--findings` | Also emit the derived mega_chan-style posture flags (no-auth, cipher-0, anon/null allowed, per-msg-auth-off, user-auth-off, KG=0). Off by default. |

## Enumeration algorithm (single session)

```
open one session (_open_session(args))
1. channel sweep: for ch in 0x0..0xF (skip 0xE self-alias):
     Get Channel Info (0x42, ch)  → success ⇒ populated; record medium/protocol/session/vendor
     (error/cc≠0 ⇒ empty; kept only if --all)
2. per populated channel:
     Get Channel Access (0x41, ch, volatile)      → access mode, priv-limit, auth-disable bits
     Get Channel Access (0x41, ch, non-volatile)  → same, saved copy
     Get Channel Auth Capabilities (0x38, ch, max_priv=Admin  [or 1..5 if --per-priv])
     Get Channel Cipher Suites (0x54, ch)          → cipher-suite list (reuse bmc-id parser)
3. discover users: Get User Access (0x44, connected-ch, user_id=1) → max_user_count
4. per user 1..max_user_count:
     Get User Name (0x46, uid)  (once per user)
     per populated channel: Get User Access (0x44, ch, uid) → priv-limit, enabled, callin, link-auth, ipmi-msg
5. assemble dict → render table | json.dumps(--json) | + findings(--findings)
close session
```

Every send is wrapped `try/except`; a failing (user,channel) or channel probe
records `err:0xNN` (or `err:timeout`) in that cell and the sweep continues —
never aborts. Rationale: BMCs are easy to DoS/wedge (mega_chan's own warning);
partial data beats a dead run.

## New protocol command

`GetChannelAccessReq` / `GetChannelAccessResp` (NetFn App `0x06`, cmd `0x41`),
added to `zipmi/scapy_ipmi/commands.py` and its dispatch table, mirroring the
existing `GetChannelInfo`/`GetUserAccess` layers.

- **Req:** byte1 = channel (bits 3:0); byte2 bits[7:6] = `01b` non-volatile /
  `10b` present-volatile (IPMI v2.0 §22.23).
- **Resp:** byte2 = `[6]` alerting-disabled, `[5]` per-msg-auth-disabled,
  `[4]` user-level-auth-disabled, `[2:0]` access mode (0=disabled,
  1=pre-boot-only, 2=always-available, 3=shared); byte3 `[3:0]` = channel
  privilege-limit.

Reused as-is: `GetChannelInfoReq` (0x42), `GetUserAccessReq` (0x44),
`GetUserNameReq` (0x46), `GetChanAuthCapsReq` (0x38),
`GetChannelCipherSuitesReq` (0x54) + `bmc_id.parse_cipher_list`.

## Relationship to the `scan` family

`zipmi scan {auth-caps, cipher-zero, all}` already probes security posture — but
**single channel** (`0xE`) at **Admin only**, no user dimension. `scan all` =
`asf-ping + auth-caps`. `user-matrix` is the multi-channel, per-user, per-priv
**generalization** of that same probing.

To avoid two divergent notions of "what's a problem":

- Factor the `0x38` auth-caps **probe+decode** into a shared helper
  (`_probe_channel_auth_caps(s, channel, max_priv)`) used by both
  `cmd_scan_auth_caps` and `user-matrix`.
- The `--findings` evaluator is **passive** — it derives flags from data already
  collected in the one session (cipher-suite list from `0x54`, anon/null/KG bits
  from `0x38`, per-msg-auth/user-auth from `0x41`/`0x38`, per-channel priv caps).
  It does **not** open new sessions. In particular the cipher-0 finding is
  *advertised-cipher-0* (suite 0 present, or anon/null enabled), **not** an active
  RAKP attempt — the active proof stays in `scan cipher-zero` (which needs its own
  cipher-0 session and thus lives outside this one-session command). The shared
  piece is the **detection rule set** (what counts as a problem), factored into
  one module both consult, so findings never disagree with a `scan` run.
- `scan`'s single-shot verbs (`auth-caps`, `cipher-zero`, `asf-ping`) stay as-is
  (fast, present-channel).

**`scan all` goes full-grid** (decided). The omnibus becomes:
`asf-ping` (sessionless) → the **full user-matrix grid** (invokes the shared
`user-matrix` enumeration) with **`--findings` ON** (a scan is a posture probe;
surfacing problems is its job). This is the one place findings default on.

Consequences:
- `scan all` now **requires/uses a session** for the user rows (it was
  sessionless asf-ping+auth-caps before). It **degrades gracefully**: with no
  creds, the sessionless half still runs (channel info/auth-caps/ciphers via
  `0x38`/`0x54`, which are pre-session) and user-access cells read
  `err:no-session`; with creds, the full grid populates.
- `scan all` and `user-matrix` call the **same enumeration function** — one
  implementation, two entry points (neutral inventory vs opinionated probe). The
  only difference is `findings` default (on for `scan all`, off for
  `user-matrix list`).

## JSON schema

```json
{
  "target": "192.168.0.23",
  "max_user_count": 16,
  "enabled_user_count": 3,
  "channels": {
    "1": {
      "medium": "802.3-LAN", "medium_raw": 4,
      "protocol": "IPMB-1.0", "protocol_raw": 1,
      "session_support": "multi-session",
      "vendor_iana": 4542,
      "access": {
        "present":     { "priv_limit": "operator", "priv_limit_raw": 3,
                         "access_mode": "always-available",
                         "per_msg_auth": true, "user_level_auth": true, "alerting": true },
        "nonvolatile": { "priv_limit": "administrator", "priv_limit_raw": 4,
                         "access_mode": "always-available",
                         "per_msg_auth": true, "user_level_auth": true, "alerting": true },
        "nv_delta":    { "priv_limit": { "present": "operator", "nonvolatile": "administrator" } }
      },
      "auth_caps": {
        "at_priv": "administrator",
        "ipmi20": true,
        "auth_types": ["md5"],
        "anon_login": false, "null_user": false, "non_null_user": true,
        "kg_zero": true, "per_msg_auth": true, "user_level_auth": true
      },
      "cipher_suites": [3, 17]
    }
  },
  "users": {
    "2": {
      "name": "root",
      "access": {
        "1":  { "priv": "operator", "priv_raw": 3, "enabled": true,
                "callin": false, "link_auth": true, "ipmi_msg": true },
        "15": { "priv": "administrator", "priv_raw": 4, "enabled": true,
                "callin": false, "link_auth": true, "ipmi_msg": true }
      }
    }
  },
  "findings": []
}
```

- `access.present` = the live (volatile) copy and the headline; `nonvolatile` =
  saved/next-boot; `nv_delta` present **only** when they differ (a scheduled
  change or runtime override — a fact, not an opinion).
- `auth_caps` is a single object by default; with `--per-priv` it becomes
  `auth_caps_by_priv: { "callback": {...}, ..., "oem": {...} }`.
- `cipher_suites` reuses the bmc-id parser output.
- Empty channels omitted unless `--all` (then `{"empty": true}`).
- `findings` empty `[]` unless `--findings`; each item
  `{ "severity": "...", "channel": N, "user": U|null, "issue": "cipher-0 enabled", ... }`.

## Human output (default)

Channel header band, then user rows × channel columns; each cell `PRIV flags`.

```
CHANNELS   1:LAN/multi/Opr*      3:LAN/multi/Adm      15:sysif/less/—
           ciphers:3,17          ciphers:3,17
USERS
2 root     Opr  E la·           Adm  E la·            Adm  E
3 admin    Adm  E la·           Opr  E la·            Adm  E
...
(cell: priv  E=enabled  la=link-auth  ci=callin  im=ipmi-msg ; * = present≠NV, see note)
Δ ch1: present priv-limit=operator, non-volatile=administrator (pending change)
```

Legend printed once. Cells that failed show `err:0xNN`.

## Error handling & safety

- Per-cell `try/except` → `err:<cc|timeout>`; run always completes.
- Default single-priv `0x38` (5× only with `--per-priv`) to limit packet volume.
- Standard `-t` timeout per send; no retries beyond the transport's existing policy.
- Read-only: no `--yes`-gated writes reachable from this command.

## Testing

- **Unit:** `GetChannelAccessResp` byte-parse — access mode enum, priv-limit,
  the three auth-disable bits, volatile vs non-volatile request encoding.
  New file `tests/unit/test_channel_access.py`.
- **Unit:** `nv_delta` computation (present==NV ⇒ absent; differ ⇒ named fields).
- **Integration:** run `user-matrix list --json` against a `vbmc` persona
  (existing zoo pattern, cf. `test_openbmc.py`), assert JSON shape: `channels`/
  `users` keys, raw+decoded fields present, one-session (single connect).
- **Findings:** with `--findings` on a persona that advertises cipher-0/anon,
  assert the corresponding finding items appear.

## Open defaults locked

- `0x38` per-priv sweep = **off by default** (`--per-priv` to enable) — DoS guard.
- Findings = **off by default** (`--findings`) — information-first.
- Channel `0xE` skipped in the sweep (self-alias, avoids double-count).
- User discovery via `Get User Access` user 1 on the connected channel.
