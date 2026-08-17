# bmc-id

**Unauthenticated BMC identification + vulnerability probe.**

`bmc-id` chains a handful of sessionless IPMI probes — plus an optional
HTTPS/Redfish grab — against a single BMC (or a whole list piped on
stdin) and emits a consolidated identification + security-posture
report. It answers, without credentials:

- *Who really makes this BMC?* (real IANA vendor, not the
  firmware-stuffed marker)
- *What generation / firmware is it?* (Dell iDRAC6/8/9, AMI MegaRAC,
  …)
- *Is it trivially ownable?* (cipher 0 / CVE-2013-4783, null user,
  weak auth)

Total cost is ~4 UDP packets plus one optional TCP/443 handshake —
cheap enough to fan out at scan velocity.

It ships as its own console script (`pip install .` →
[`bmc-id`](pyproject.toml) on `$PATH`); the runnable copy also lives
at [`examples/bmc-id`](examples/bmc-id) and the implementation at
[`zipmi/cli/bmc_id.py`](zipmi/cli/bmc_id.py).

---

## TL;DR

```bash
# single host, full report
bmc-id 192.168.0.23

# UDP-only (skip HTTPS + Redfish), tighter timeout
bmc-id 192.168.0.23 -t 2 --no-https

# scan a list, one TSV line per host
bmc-id -q < targets.txt
zmap -p623 ... | awk '{print $1}' | bmc-id -q

# machine-readable
bmc-id --json 10.0.0.0/24 > fleet.json
```

---

## Why not just read the OEM IANA?

`Get Channel Auth Capabilities` alone classifies ~95% of the public
BMC fleet at the firmware-family level. But the OEM IANA in that
response is frequently a **firmware-stuffed marker**, not the real
silicon vendor — e.g. `0x005345` is ASCII `"ES"`, used by *every* AMI
MegaRAC regardless of who rebadged it.

`bmc-id` cross-checks three independent signals to resolve that
ambiguity and push confidence from ~86% to ~99%:

1. the IPMI **tuple** (auth/status/ext capability bits) → fleet
   cluster,
2. `Get Device ID`'s **registered IANA PEN** + product ID + firmware,
3. an **HTTPS/Redfish** grab that disambiguates rebadged AMI variants
   (Supermicro vs ASRockRack vs ASUS vs generic-Quanta).

When all three agree, the verdict is reported as high confidence; when
they conflict, that conflict is surfaced rather than hidden.

---

## What it probes

| # | Probe | NetFn/Cmd | Yields |
|---|-------|-----------|--------|
| 1 | Get Channel Auth Capabilities | `0x06 / 0x38` | IPMI **tuple**; security posture (cipher-0 likelihood, null user, MD5/MD2/StraightPwd auth); fleet-vendor lookup via `tuple_map.json` |
| 2 | Get Device ID | `0x06 / 0x01` | Real manufacturer IANA PEN, product_id, firmware revision; BMC generation guess (`consts.BMC_GENERATION` + heuristic) |
| 3 | Get System GUID | `0x06 / 0x37` | 16-byte UUID; reflector-detection signal (many IPs in a /24 sharing one GUID ⇒ a single canned middlebox); embedded MAC OUI extraction (RFC 4122 v1) |
| 4 | Get Channel Cipher Suites | `0x06 / 0x54` | Enumerated cipher list; flags **cipher 0** (CVE-2013-4783) if advertised |
| 5 | HTTPS grab (TCP/443) | — | Cert CN / issuer / SAN, `Server` header, page title; resolves Supermicro vs ASRockRack vs generic-AMI ambiguity that pure IPMI tuples cannot |
| 6 | Redfish grab | — | Service-root / vendor strings (best-effort; skipped with `--no-https`) |

All IPMI probes are sessionless and unauthenticated. `bmc-id` also
contains active liveness probes (`probe_active_v15` /
`probe_active_v20`) and an explicit cipher-0 RAKP attempt
(`probe_cipher0_active`) used to *confirm* rather than merely infer the
cipher-0 weakness.

---

## How it works

### The IPMI "tuple"

The `Get Channel Auth Capabilities` reply packs four bytes of
capability bits — auth types, channel status, extended caps, OEM
field. Decoded and concatenated into a stable key:

```
ch1_a86_s14_e03_o000000
 │   │   │   │   └─ OEM IANA field (often a stuffed marker)
 │   │   │   └───── extended capability bits
 │   │   └───────── channel status bits
 │   └───────────── auth-type bitmask
 └───────────────── channel number
```

This **tuple** is a remarkably stable per-firmware-family fingerprint.
`bmc-id` looks it up in a fleet knowledge base (`tuple_map.json`, a
76-cluster table built from large-scale internet IPMI scans) to map
the tuple → likely vendor/firmware family and a confidence weight.

### Real vendor vs stuffed marker

`Get Device ID` returns the **registered** IANA Private Enterprise
Number, the product ID, and the firmware revision. `bmc-id` maps these
through `zipmi.consts` (`IANA`, `BMC_GENERATION`,
`guess_bmc_generation`) to a concrete generation (e.g. Dell
product_id `0x0100` → *iDRAC6 (Monolithic)*). This is the ground-truth
vendor signal that overrides a stuffed OEM marker.

### GUID forensics

`Get System GUID` returns 16 bytes. `bmc-id`:

- detects **RFC 4122 v1** GUIDs and extracts the embedded MAC + OUI
  (some BMCs derive the node field from the NIC MAC — a second vendor
  signal, and a host identifier),
- treats a GUID shared across many addresses in a subnet as a
  **reflector / middlebox** indicator rather than a real fleet.

### Confidence scoring

Signals are collected (`_collect_signals`) and scored into a labelled
confidence (`conf_label` / `fmt_conf`). Agreement across the tuple,
the registered IANA, and the HTTPS/Redfish identity raises confidence;
disagreement is reported (`same_vendor` / `_vendor_family`), so a
rebadge or a lying marker shows up as a conflict instead of a false
high-confidence verdict.

### Vulnerability flags

- **cipher 0 / CVE-2013-4783** — flagged if advertised in the cipher
  list and (where possible) confirmed by an active cipher-0 RAKP
  exchange.
- **null user / weak auth** — derived from the auth-capability bits
  (MD5 vs MD2 vs StraightPwd, anonymous-login bit).

---

## CLI

```
bmc-id [TARGETS ...] [options]
```

Targets are IPs, hostnames, or CIDR ranges on argv. **If no targets
are given and stdin is not a TTY, targets are read from stdin** (one
per line) — the scan-pipeline mode. Mix any of the forms.

| Flag | Effect |
|------|--------|
| `-t SEC` | Per-probe timeout in seconds (default `3.0`; iDRAC6 wants ~5) |
| `-v` | Verbose: per-probe progress to stderr |
| `-q`, `--quiet` | One TSV line per host: `ip⇥vendor⇥conf⇥source` |
| `-j`, `--json` | JSON: per-target objects under `{"targets": {...}}` |
| `--no-https` | Skip the HTTPS **and** Redfish probes (UDP-only) |
| `--tuple-map PATH` | Custom `tuple_map.json` (default: bundled `zipmi/data/zmap-ipmi-decode/tuple_map.json`) |
| `--kb-dir PATH` | Custom knowledge-base dir (default: bundled `zipmi/data/zmap-ipmi-decode/kb`) |

**Exit status:** `0` if at least one probe decoded for at least one
target; `1` if every probe failed.

---

## Output modes

### Full report (default)

```
$ bmc-id 192.168.0.23
target: 192.168.0.23
──── Get Channel Auth Caps ────
tuple        = ch1_a86_s14_e03_o000000
...
──── Get Device ID ────
manufacturer = 674 (Dell)
product_id   = 0x0100 → iDRAC6 (Monolithic)
fw_revision  = 2.92
...
──── Get System GUID ────
guid         = a8b0c0d0-e0f0-1020-3040-506070809000
...
──── Get Channel Cipher Suites ────
cipher_list  = [0,1,2,3,6,7,8,11,12,17]   ⚠ CIPHER 0 ENABLED
──── HTTPS :443 ────
server       = Mbedthis-Appweb/2.4.2
cert_cn      = idrac-S1NCD8X
page_title   = iDRAC6 Login

─────────── verdict ───────────
family       = Dell iDRAC6 (real vendor 674; matches tuple cluster)
confidence   = high (3 independent signals agree)
```

### `-q` / `--quiet` — one line per host

Tab-separated `ip ⇥ vendor ⇥ confidence ⇥ source`, ideal for sorting
and bucketing a large scan:

```
192.168.0.23	Dell iDRAC6	high	tuple+did+https
10.0.0.7	AMI MegaRAC	med	tuple-only
10.0.0.9	no-signal	-	-
```

### `-j` / `--json` — machine-readable

```json
{ "targets": { "192.168.0.23": { "auth_caps": {...}, "device_id": {...},
  "guid": {...}, "ciphers": {...}, "https": {...}, "verdict": {...} } } }
```

---

## Scanning at scale

`bmc-id` is built to sit at the end of a discovery pipeline:

```bash
# zmap UDP/623 → bmc-id classification → CSV
zmap -p 623 -M udp --probe-args=file:ipmi_probe.pkt 0.0.0.0/0 \
  | awk '{print $1}' \
  | bmc-id -q --no-https -t 2 \
  | sort -t$'\t' -k2,2 > fleet.tsv
```

`--no-https` keeps it pure-UDP (no TCP fan-out, faster, stealthier);
drop it when you want the HTTPS/Redfish disambiguation on hosts of
interest.

---

## The fleet knowledge base (optional)

The tuple→vendor mapping and KB ship **bundled** with the package
(`zipmi/data/zmap-ipmi-decode/`); they're derived from large-scale scan
data. `bmc-id` degrades gracefully without them:

- **no `tuple_map.json`** → the report still shows the decoded tuple,
  device-ID vendor, ciphers, GUID, and HTTPS identity; only the
  *fleet-cluster* attribution is omitted (verdict source shows
  `tuple-only` / device-ID-only).
- point `--tuple-map` / `--kb-dir` at your own copies to restore full
  attribution.

---

## Related

- [`examples/bmc-id`](examples/bmc-id) — runnable copy
- [`zipmi/cli/bmc_id.py`](zipmi/cli/bmc_id.py) — implementation
- [`examples/01_get_chan_auth_caps.py`](examples) — single-probe baseline
- [`zipmi/scapy_ipmi/commands.py`](zipmi/scapy_ipmi/commands.py) — the request layers used
- [`zipmi/consts.py`](zipmi/consts.py) — `IANA`, `BMC_GENERATION`, `guess_bmc_generation`
- the "What is an IPMI tuple?" writeup (author's external research corpus, not in this repo)
