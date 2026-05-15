# `zipmi fuzz` — fuzzer surface

Four fuzz harnesses, each targeting a different layer of the IPMI stack.
Run `zipmi fuzz list` to see them all from the CLI.

| Verb     | Module                         | Layer probed                    | Auth needed? |
|----------|--------------------------------|---------------------------------|--------------|
| `sweep`  | `zipmi.fuzz.sweep`             | NetFn × Cmd dispatch surface    | yes — needs an active session |
| `rakp`   | `zipmi.fuzz.rakp_mut`          | RAKP1 message field validation  | no — pre-auth |
| `length` | `zipmi.fuzz.length`            | IPMI 1.5 `msg_length` parser    | yes — needs an active 1.5 session |
| `cipher` | `zipmi.fuzz.cipher_confuse`    | RMCP+ Open Session algorithm IDs | no — pre-auth |

## Why four — what each one catches

- **sweep** — finds undocumented OEM cmds, missing handlers, parser
  crashes on empty data, side-channel timing on individual cmds. The
  output is a coverage map: which `(NetFn, cmd)` pairs the BMC actually
  recognises. See `docs/fuzz-sweep.md` for verbosity flags + bucket
  semantics.

- **rakp** — RAKP is a hand-rolled mini-protocol with several length-
  prefixed fields (nonce, role, user_name) and tight role-byte rules.
  Mutations probe for parse-time bugs and auth-bypass surfaces. CVE-
  2013-4786 (Farmer's WOOT13 paper, cipher 0 + null user) is the
  canonical example; this harness catches the next round of variants.
  Pre-auth — works against any reachable BMC.

- **length** — IPMI 1.5 puts a single `u8 msg_length` byte in front of
  the IPMB body. A careless BMC that trusts the field can be coerced
  into reading off-buffer data into the response, or accepting truncated
  requests as valid. Four mutations: `zero`, `truncated`, `oversized`,
  `byte-max` (0xFF). Requires an active 1.5 session (the path is post-
  auth precisely because the bug class is "what does the parser do
  *after* I'm in?"). RMCP+ has its own framing layer — that's the next
  fuzzer's job.

- **cipher** — RMCP+ Open Session Request advertises algorithm IDs
  for auth, integrity, and confidentiality (3 separate u8 fields).
  Many BMCs only validate the suite_id and trust the per-field bytes,
  so claiming `auth=HMAC-SHA1, integrity=NONE, conf=AES-CBC-128` can
  produce an integrity-less but encrypted session. Mutations cover
  reserved 0xFF in each field, mismatch combos, and the canonical
  cipher-0 path. Pre-auth.

## Status decoding (cipher fuzzer)

The `cipher` fuzzer prints `rmcp_status` byte +1 of the Open Session
Response payload. Codes from IPMI 2.0 spec table 13-15:

| Code  | Meaning                                                     |
|------:|-------------------------------------------------------------|
| 0x00  | no errors (session opened)                                  |
| 0x04  | invalid authentication algorithm                            |
| 0x05  | invalid integrity algorithm                                 |
| 0x10  | invalid confidentiality algorithm                           |
| 0x11  | no Cipher Suite match with proposed security algorithms     |
| 0x12  | illegal or unrecognized parameter                           |

The full table is in `zipmi.fuzz.cipher_confuse.RMCP_STATUS`.

Status `0x12` on a reserved-byte mutation means the BMC validated the
field strictly. Status `0x00` despite a bogus alg byte is a **fail-open**
finding worth investigating.

## Live results (Dell PowerEdge T710 / iDRAC6 1.70)

- `fuzz sweep --netfn 0x06`: 51 BMC responded, 202 BMC rejected (0xC1),
  0 errors, 3 skipped.
- `fuzz cipher`: all 7 mutations rejected with rmcp_status `0x12`
  ("illegal or unrecognized parameter"). Dell iDRAC6 1.70 strictly
  validates per-field algorithm bytes.
- `fuzz length`: all 4 mutations time out with no reply. Dell BMC
  silently drops corrupted-length packets at the link layer rather than
  echoing a parser error. Defensive but opaque (no observable response
  to differentiate "rejected" from "transport drop").
- `fuzz rakp`: baseline succeeds (0x00); nonce / role / empty-name /
  msg_tag mutations rejected with 0x12 ("illegal or unrecognized
  parameter"); `namelen_lie_short` and `namelen_lie_long` trigger a
  different code — 0x0c ("invalid name length"). That divergence
  reveals Dell has a specific length validator running ahead of the
  generic parameter check — useful RE intel for future bug hunting.
- `fuzz rakp` oversize-pad mutations (baseline RAKP1 padded with 0xFF
  to N bytes): `1472` (single MTU frame), `1500` (2 IP fragments),
  `8000` (multi-fragment) all bounce off the **same 0x0c name-length
  validator** as `namelen_lie_*`. **`16000`, `32000`, `65000` silently
  drop** — Dell's RAKP1 receive buffer ceiling is between 8000 and
  16000 bytes; oversize packets get binned at the link/IP layer before
  reaching the parser.
- `fuzz rakp` **combined `name_len` × `pad` mutations**:
  `namelen0xFF_pad_8000` (claim 255, pad to 8000),
  `namelen0xFF_no_pad` (claim 255, default size),
  `namelen1_pad_8000` (claim 1, pad to 8000) — **all three return
  0x0c**. Confirms Dell iDRAC6 1.70 uses **strict total-length
  validation**: the validator requires `wire_payload_size == 28 + 1 +
  name_len` exactly. Any mismatch → 0x0c. Validation order is also
  visible:
    1. **Length validator first** → 0x0c on mismatch
    2. **Content validator second** → 0x12 / 0x0c-other / 0x00
  Evidence: `empty_username` returns 0x12 (length matched
  `28 + 1 + 0`, content failed) while `namelen_lie_short/long`
  return 0x0c (length mismatched, never reached content check).
  This is **defensive implementation** — no buffer over-read surface
  via name_len misclaiming on this firmware. Cheaper BMCs in the
  same generation likely behave differently; running this fuzzer
  against a Supermicro / HP iLO would be informative.

## Live results tables (Dell PowerEdge T710 / iDRAC6 1.70)

Captured 2026-05-02 against `192.168.0.23`. Re-run with
`zipmi fuzz <verb> -v` (sweep / rakp) or no flag (cipher / length).

### `fuzz sweep --netfn 0x06`

| Bucket                       | Count |
|------------------------------|------:|
| BMC responded                |    51 |
| BMC rejected (0xC1)          |   202 |
| transport / parse errors     |     0 |
| skipped (destructive)        |     3 |

Notable individual rows: `0x39 GetSessionChallenge` returns
`0xd5 Command not supported in present state` (we already have a
session); `0x05`/`0x06`/`0x09..0x0d` return `0xc7 Request data length
invalid` (handlers reachable but expect non-empty data).

### `fuzz rakp` — full mutation table

| Mutation              | Status | meaning                                  |
|-----------------------|:------:|------------------------------------------|
| `baseline`            | `0x00` | no errors (auth_code 20B)                |
| `nonce_zeros`         | `0x12` | illegal or unrecognized parameter        |
| `nonce_ones`          | `0x12` | illegal or unrecognized parameter        |
| `role_top_bits`       | `0x12` | illegal or unrecognized parameter        |
| `role_zero`           | `0x12` | illegal or unrecognized parameter        |
| `empty_username`      | `0x12` | illegal or unrecognized parameter        |
| `namelen_lie_short`   | `0x0c` | invalid name length                      |
| `namelen_lie_long`    | `0x0c` | invalid name length                      |
| `msg_tag_max`         | `0x12` | illegal or unrecognized parameter        |
| `oversize_pad_1472`   | `0x0c` | invalid name length (single MTU frame)   |
| `oversize_pad_1500`   | `0x0c` | invalid name length (2 IP fragments)     |
| `oversize_pad_8000`   | `0x0c` | invalid name length (multi-fragment)     |
| `oversize_pad_16000`  |   —    | [no reply] — receive buffer ceiling      |
| `oversize_pad_32000`  |   —    | [no reply]                               |
| `oversize_pad_65000`  |   —    | [no reply]                               |
| `namelen0xFF_pad_8000`| `0x0c` | invalid name length                      |
| `namelen0xFF_no_pad`  | `0x0c` | invalid name length                      |
| `namelen1_pad_8000`   | `0x0c` | invalid name length                      |

Key inferences (see prose above for derivation):

- Strict total-length validator: `wire_payload == 28 + 1 + name_len`.
- Length check runs before content check (0x0c precedes 0x12).
- Receive-buffer ceiling between 8 KB and 16 KB.
- No buffer over-read surface via `name_len` misclaim on this fw.

### `fuzz cipher` — full mutation table

All 7 mutations rejected with `rmcp_status = 0x12` ("illegal or
unrecognized parameter"). Dell strictly validates per-field algorithm
bytes — no fail-open behavior on this firmware.

| Mutation                       | A/I/C       | Status | meaning                              |
|--------------------------------|-------------|:------:|--------------------------------------|
| `auth_reserved_0xFF`           | `ff/00/00`  | `0x12` | illegal or unrecognized parameter    |
| `integrity_reserved_0xFF`      | `01/ff/00`  | `0x12` | illegal or unrecognized parameter    |
| `conf_reserved_0xFF`           | `01/01/ff`  | `0x12` | illegal or unrecognized parameter    |
| `mismatch_auth_no_integrity`   | `01/00/01`  | `0x12` | illegal or unrecognized parameter    |
| `all_zero_explicit`            | `00/00/00`  | `0x12` | illegal or unrecognized parameter    |
| `auth_md5_legacy`              | `02/00/00`  | `0x12` | illegal or unrecognized parameter    |
| `integrity_only`               | `00/01/00`  | `0x12` | illegal or unrecognized parameter    |

### `fuzz length --netfn 0x06 --cmd 0x01`

All 4 mutations time out — Dell silently drops corrupted-length
packets at the link / parser layer with no reply.

| Mutation     | sent_msg_length | actual_ipmb_len | reply        |
|--------------|----------------:|----------------:|--------------|
| `zero`       |               0 |               7 | [no reply]   |
| `truncated`  |               6 |               7 | [no reply]   |
| `oversized`  |              23 |               7 | [no reply]   |
| `byte-max`   |             255 |               7 | [no reply]   |

Defensive but opaque: no observable response means we cannot
differentiate "rejected by parser" from "dropped at link layer". A
target where `oversized` returned data while `truncated` was silent
would be a much more interesting finding.

## Implementation notes

- `length` requires IPMI 1.5 because RMCP+ has a 16-bit explicit payload
  length, not the 1.5 single-byte field. CLI errors out cleanly if
  invoked with `-I lanplus`.
- `cipher` is pre-auth — opens a UDP socket, sends Open Session Request,
  reads Open Session Response. No `_open_session()` call. That's why
  the fuzzer can run against locked-out BMCs (no creds needed).
- `sweep` and `rakp` ship streaming output; `length` and `cipher` finish
  fast enough (4 and 7 packets respectively) that batched output is
  fine. If a future variant grows past ~30 mutations, add streaming.

## Updating

When adding a new fuzz module:

1. Drop the module in `zipmi/fuzz/`, with the standard header (WHAT/WHY/
   USAGE/SUCCESS/TARGET/RELATED).
2. Add a CLI handler `cmd_fuzz_<name>` and an argparse subparser.
3. Register the verb + module in this table AND in
   `cmd_fuzz_list`'s `rows` list (`zipmi/cli/zipmi.py`).
4. Update `docs/architecture.md` module map.
5. The pre-commit guard (`scripts/check_doc_sync.py`) will widen to
   verify each `zipmi.fuzz.*` module appears in the CLI registry and
   in this doc — see step 4 in the BMC_GENERATION update procedure for
   the pattern.
