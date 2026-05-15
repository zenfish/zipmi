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
