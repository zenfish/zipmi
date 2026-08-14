# IPMI 2.0 RMCP+ / RAKP — implementation notes

State machine and wire-format notes for the lanplus path. All formulas
verified byte-for-byte against `ipmitool -I lanplus -A MD5 -C 3` against
Dell iDRAC6 (FW 1.70).

## State machine

```
Client                                   BMC
------                                   ---
Open Session Request (ptype 0x10)  -->
                                   <--   Open Session Response (0x11)
                                         (returns managed_session_id)

RAKP Message 1 (ptype 0x12)        -->
  - random R_c
  - role (0x14 = name-only-lookup + admin)
  - user name
                                   <--   RAKP Message 2 (0x13)
                                         - random R_m
                                         - GUID_m
                                         - HMAC auth code (BMC's)

  verify HMAC = HMAC(K_uid, sid_c||sid_m||R_c||R_m||GUID||role||ulen||uname)
  derive SIK  = HMAC(K_uid, R_c||R_m||role||ulen||uname)
  derive K1   = HMAC(SIK, 0x01 * 20)
  derive K2   = HMAC(SIK, 0x02 * 20)

RAKP Message 3 (ptype 0x14)        -->
  - HMAC(K_uid, R_m||sid_c||role||ulen||uname)
                                   <--   RAKP Message 4 (0x15)
                                         - integrity check value
                                           = HMAC(SIK, R_c||sid_m||GUID)[:12]

Set Session Privilege Level (encrypted+authenticated IPMI msg)  -->
                                   <--   Response

[normal IPMI commands, all encrypted+authenticated]

Close Session                      -->
```

## Cipher suite 3 (the default)

| Component       | Algorithm        | Output size | Notes                       |
|-----------------|------------------|-------------|-----------------------------|
| Auth            | HMAC-SHA1        | 20 bytes    | uses K_uid (NUL-padded pw)  |
| Integrity       | HMAC-SHA1-96     | 12 bytes    | uses K1                      |
| Confidentiality | AES-CBC-128      | (16-byte block) | uses K2[0:16], IV per msg |

Cipher suite IDs and combos live in `zipmi.scapy_ipmi.crypto.CIPHER_SUITES`.

## Full standard suite coverage (0–19)

zipmi implements **every standard cipher suite 0–19** — the SHA1 family (0–5), the
MD5 families (6–14), and the **SHA256 family (15–19)** added by Errata 4 — including
the RC4/MD5 suites that **ipmitool and FreeIPMI never implemented**:

| Suites | Auth / Integrity / Conf | Status |
|--------|-------------------------|--------|
| 0–3, 6–8, 15–17 | none/SHA1/MD5/SHA256, none·AES | verified (baseline) |
| **11, 12** | HMAC-MD5 / **MD5-128 (alg 3)** / none·AES | **oracle-verified** ✓ |
| **4, 5, 9, 10, 13, 14, 18, 19** | … / **xRC4-128/40 (conf 2/3)** | spec-faithful, **unvalidated** ⚠ |

(15 = SHA256/none/none, 16 = SHA256/SHA256-128/none, 17 = …/AES, 18 = …/xRC4-128,
19 = …/xRC4-40 — mirroring the SHA1 block 1–5.)

**MD5-128 integrity (alg 3)** — used by suites 11–14. Unlike the HMAC integrity
algorithms (keyed with the SIK-derived K1), it is a plain keyed MD5 over the
**password (Kuid)**: `AuthCode = MD5(PW20 ‖ data ‖ PW20)`, password zero-padded to
20 bytes, full 16-byte output (IPMI 2.0 §13.28.4). Matches FreeIPMI's reference
and the `MD5_128` symbol in Supermicro's own `libipmicrypt`. Verified live against
a Supermicro X10 (the `vbmc x10` box): `-C 11` and `-C 12` establish full sessions.

**xRC4 confidentiality (conf 2/3)** — suites 4,5,9,10,13,14,18,19. `KRC = MD5(K2 ‖ IV)`
(xRC4-128 uses all 16 bytes, xRC4-40 the top 5); confidentiality header =
4-byte data-offset + 16-byte IV (IV present only at offset 0); no trailer
(§13.30). Every stack we examined skips xRC4 — ipmitool `assert`s AES-only,
FreeIPMI has it as a `TODO`, and Supermicro's own `libipmicrypt` *advertises*
suites 4,5,9,10,13,14,18,19 while carrying **no `rc4` symbol at all** (so it
`0x11`-rejects them at Open Session). So this may be the only working xRC4 impl —
but we didn't survey everything, so treat that as unconfirmed, not a claim.

> **Still hunting a BMC that actually negotiates xRC4 to validate against.** If
> yours does, please test it and let us know:
>
> ```
> zipmi -C 4 -H <bmc-ip> -U <user> -P <pass> mc info    # xRC4-128 (sha1)
> zipmi -C 5 -H <bmc-ip> -U <user> -P <pass> mc info    # xRC4-40  (sha1)
> ```
>
> `-C N` is explicit, so there's no fallback — it's a pure xRC4 test. If it prints
> the BMC's manufacturer/firmware, the session encrypted **and** decrypted a real
> command over xRC4 end-to-end → the implementation is correct; open an issue and
> tell us the vendor/model/firmware. `Open Session: status 0x11` means that BMC
> advertises the suite but won't negotiate it (like the Supermicro X10). Suites
> 9/10 (md5) and 13/14 (md5-128) exercise the same xRC4 keystream with different
> auth/integrity.

## In-session message framing

Every authenticated+encrypted IPMI message:

```
+---------+-----+---------+----------+----------+---------+-----------+----------+
| RMCP    | 06  | type    | sid (LE) | seq (LE) | len LE  | encrypted | trailer  |
| (4 B)   | (1) | (1)     | (4)      | (4)      | (2)     | body      | + HMAC   |
+---------+-----+---------+----------+----------+---------+-----------+----------+
                                                            \         / \   12  /
                                                             \-------/   \----/
                                                              len bytes   AuthCode
```

`type` byte: bit 7 = encrypted, bit 6 = authenticated, bits 5..0 = payload type.

`encrypted body` for cipher 3 = `[16-byte IV][AES-CBC ciphertext][pad][pad-length]`
where pad bytes are `01 02 ... padNum` and pad-length is the count
(IPMI 2.0 §13.29.3, NOT PKCS).

`trailer` = integrity pad bytes (0xFF) so the next-header byte sits on
a 4-byte boundary, then 1 byte pad-length, then 1 byte next-header
(value 0x07 = "session trailer").

`AuthCode` = HMAC over auth_type through next-header, truncated per the
cipher suite's integrity_alg.

## Gotchas observed

### Field naming collision in Scapy

A `StrLenField` named `payload` on a `Packet` collides with Scapy's
internal payload chain attribute and breaks `bytes(p)` with
`clone_with() got multiple values for keyword argument 'payload'`.
Use a different name (we use `body`, then dropped it entirely in
favour of the natural Scapy chain).

### `bytes(packet.payload)` returns chained Padding too

Scapy's `extract_padding` on `IPMI20_Session` splits encrypted body
(payload) from trailer (padding). But `bytes(sess.payload)` walks the
whole chain, including the Padding layer. To get just the payload-len
bytes, use `sess[Raw].load[:sess.payload_length]`.

### RMCP class 7 ambiguity

`RMCP class==7` covers both IPMI 1.5 and 2.0. Disambiguate via
`IPMI15_Session.dispatch_hook`: peek at the leading byte; if it's 0x06
(RMCP+ marker), reroute to IPMI20_Session.

### Cipher suite 3 in modern BMCs sometimes uses HMAC-SHA256

Per the IPMI 2.0 errata: some BMCs negotiate suite 3 but actually use
HMAC-SHA256-128 for integrity. We don't auto-detect; the spec ID is
authoritative on Dell iDRAC6.

## Verification (Dell iDRAC6 192.168.0.23)

```
$ zipmi -I lanplus -C 3 mc info
Device ID                 : 32
Device Revision           : 0
Firmware Revision         : 1.70
IPMI Version              : 0x02
Manufacturer ID           : 674
Manufacturer Name         : Dell
Product ID                : 256 (0x0100)
Device Available          : yes
Provides Device SDRs      : yes
Additional Device Support : 0xdf
```

Identical fields to `ipmitool -I lanplus -C 3 mc info`. RAKP HMACs and
ICV match the oracle pcap byte-for-byte (see `tests/unit/test_rakp.py`).

## Cipher-suite auto-selection (test-first, like ipmitool)

When you don't pass `-C/--cipher`, zipmi **discovers** the right suite instead of
guessing: before opening the session it sends **Get Channel Cipher Suites**
(App NetFn `0x06`, cmd `0x54`) — unauthenticated, pre-session — reads what the BMC
supports, and picks the strongest. An explicit `-C N` is honored verbatim and skips
discovery.

**Fallback ladder (auto only):** the offered suites are ranked strongest→weakest and
tried in order — if the strongest doesn't actually *establish* (e.g. a BMC that
advertises xRC4 in `0x54` but rejects it at Open Session with status `0x11`), zipmi
transparently falls back to the next-best and emits a `[note]` (`cipher suite N did
not establish …; trying next: M` → `fell back to cipher suite M`). An explicit `-C N`
gets exactly one attempt and a hard error on failure — your choice, your problem.

```
zipmi -I lanplus -H bmc -U root -P pass mc info      # auto: queries 0x54, picks best
zipmi -C 17      -H bmc -U root -P pass mc info       # force suite 17
```

### What "strongest" means (computed, not hand-listed)

`Session._cipher_strength` scores each suite lexicographically on three axes,
**auth-primary** — the RAKP auth algorithm gates authentication, the offline-crackable
RAKP hash, *and* the KDF that derives the integrity/confidentiality session keys:

1. auth: **SHA256 > SHA1 > MD5 > none**
2. confidentiality: **AES-CBC-128 > xRC4-128 > xRC4-40 > none**
3. integrity: **SHA256-128 > SHA1-96 > MD5-128 > none**

For the suites zipmi implements that gives `17 > 3 > 2 > 1 > 8 > 7 > 6`. Note SHA1
(3/2/1) ranks **above** MD5 (8/7/6), and an AES suite beats a plaintext one of equal
auth — computing this avoids the easy mistake of hand-ordering it wrong.

### Cipher 0 and weak suites

- **Never a silent unauthenticated downgrade:** any authenticated suite is preferred
  over suite 0. But if the BMC offers *only* cipher 0, zipmi uses it — working beats
  failing — rather than falling back to a suite the BMC rejects.
- **Fallback:** if discovery returns nothing usable (BMC ignored `0x54`), zipmi uses
  suite **3** (the spec-mandatory suite).
- **stderr notices** (informative, never fatal, stdout stays clean):
  - auto-select landed on a suite other than 3 → `note: auto-selected cipher suite N …`
  - the resolved suite (auto *or* explicit `-C`) has **no auth** or **no integrity** →
    `warning: cipher suite N — NO authentication …/no integrity protection …`

### Why this matters

The IPMI 2.0 spec makes **cipher suite 3** (RAKP-HMAC-SHA1 / HMAC-SHA1-96 /
AES-CBC-128) *mandatory-to-implement*, and makes the `0x54` discovery *optional*
for clients. So historically a client could just default to suite 3 and rely on the
spec's guarantee. But security-hardened BMCs — e.g. current OpenBMC — **drop SHA1**
and advertise **cipher suite 17 only** (RAKP-HMAC-SHA256). Against those, a client
that blindly proposes suite 3 gets RMCP+ Open Session status `0x04`
("invalid authentication algorithm") and fails.

Doing the `0x54` query first makes zipmi interoperate with both worlds — legacy
BMCs that offer 3, and SHA1-dropping BMCs that offer only 17 — without the user
needing to know which. This is exactly what `ipmitool` does ("Using best available
cipher suite N"); FreeIPMI and older zipmi instead default to 3 and require you to
pass the suite explicitly.

| client | default with no cipher flag | queries `0x54`? |
|--------|-----------------------------|-----------------|
| ipmitool 1.8.19 | best available (auto) | yes |
| freeipmi 1.6.15 | suite 3 (fixed)       | no  |
| **zipmi** (this change) | **best available (auto)** | **yes** |

### Record parsing note

`0x54` responses come in two shapes and `parse_cipher_suite_records()` handles both:
the standard Cipher Suite Record (`C0 <id> <algs>` / `C1 <iana:3> <id> <algs>`), and
the **bare tagged-algorithm** form OpenBMC returns (algorithm bytes only, tag in
bits[7:6] = 00 auth / 01 integrity / 10 confidentiality). For the bare form the
completed `(auth, integ, conf)` triple is reverse-mapped to a suite ID via
`CIPHER_SUITES` — e.g. OpenBMC's `03 44 81` → suite 17. See
`tests/unit/test_rakp.py::test_cipher_records_*`.
