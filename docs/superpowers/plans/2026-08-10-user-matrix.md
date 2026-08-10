# user-matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `zipmi user-matrix list` — a one-session, read-only enumeration of the full user × channel privilege/auth/cipher grid, with information-first JSON output and an optional derived `--findings` layer; and make `scan all` run the same full grid.

**Architecture:** A new protocol class `GetChannelAccess (0x41)` in `commands.py`; all enumeration/decode/render/findings logic in a new focused module `zipmi/cli/user_matrix.py` written against an injected `send`-capable session (so it unit-tests with a fake, no BMC); a thin `cmd_user_matrix_list` wrapper + subparser in `zipmi.py`; and `scan all` calls the same builder with findings on.

**Tech Stack:** Python 3.11+, scapy Packet layers, pytest. No new dependencies.

## Global Constraints

- **One session.** All queries run inside a single `_open_session(args)` context; never a session per channel. `0x38`/`0x54` answer in-session fine.
- **Read-only.** No `--yes`-gated writes reachable from this command.
- **Information-first.** Core output is faithful facts; `--findings` (derived) is off by default, on only for `scan all`.
- **Findings are passive** — derived from data already collected; never open a new session (no active cipher-0 RAKP here).
- **Non-fatal per-cell errors** — a failing (user,channel)/channel probe records `err:<cc|timeout>`; the run always completes.
- **Skip channel `0xE`** in the sweep (self-alias).
- Follow existing patterns: `cmd_*` wrappers + `set_defaults(func=...)` subparsers in `zipmi.py`; scapy classes mirror `GetChannelInfoReq/Resp`.

---

### Task 1: `GetChannelAccess (0x41)` protocol classes + dispatch

**Files:**
- Modify: `zipmi/scapy_ipmi/commands.py` (add classes near `GetChannelInfoResp` ~line 452; add dispatch entry in the `CMD_PAYLOADS` map ~line 903)
- Test: `tests/unit/test_channel_access.py`

**Interfaces:**
- Produces: `GetChannelAccessReq(channel:int, access_type:int)`, `GetChannelAccessResp` with fields `comp_code`, `access_byte`, `priv_byte`. `access_type` = `0b01` non-volatile, `0b10` present-volatile (occupies the top 2 bits of request byte 2).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_channel_access.py
from zipmi.scapy_ipmi.commands import GetChannelAccessReq, GetChannelAccessResp


def test_req_encodes_channel_and_access_type():
    # present-volatile (0b10) on channel 1 → bytes: 01, (0b10 << 6)=0x80
    raw = bytes(GetChannelAccessReq(channel=1, access_type=0b10))
    assert raw == bytes([0x01, 0x80])
    # non-volatile (0b01) → second byte 0x40
    raw_nv = bytes(GetChannelAccessReq(channel=1, access_type=0b01))
    assert raw_nv == bytes([0x01, 0x40])


def test_resp_parses_access_and_priv_bytes():
    # comp_code 0, access_byte 0x22 (access-mode 2 + per-msg-auth-disabled bit5),
    # priv_byte 0x04 (Administrator)
    r = GetChannelAccessResp(bytes([0x00, 0x22, 0x04]))
    assert r.comp_code == 0x00
    assert r.access_byte == 0x22
    assert r.priv_byte == 0x04
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_channel_access.py -v`
Expected: FAIL with `ImportError: cannot import name 'GetChannelAccessReq'`

- [ ] **Step 3: Write minimal implementation**

Add to `zipmi/scapy_ipmi/commands.py` immediately after `GetChannelInfoResp` (the `extract_padding` that returns `b"", s`):

```python
class GetChannelAccessReq(Packet):
    name = "Get Channel Access Request"
    fields_desc = [
        ByteField("channel", 0xE),           # bits 3:0 = channel number
        # byte 2 bits [7:6] select which copy (IPMI 2.0 §22.23):
        #   01b = non-volatile, 10b = present volatile
        BitField("access_type", 0b10, 2),
        BitField("reserved", 0, 6),
    ]

    def extract_padding(self, s):
        return b"", s


class GetChannelAccessResp(Packet):
    name = "Get Channel Access Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        # byte 2: [6] alerting-disabled, [5] per-msg-auth-disabled,
        #         [4] user-level-auth-disabled, [2:0] access mode
        XByteField("access_byte", 0x00),
        # byte 3: [3:0] channel privilege-limit
        XByteField("priv_byte", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s
```

Add to the `CMD_PAYLOADS` dict (after the `(0x06, 0x42)` line):

```python
    (0x06, 0x41): (GetChannelAccessReq,     GetChannelAccessResp),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_channel_access.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add zipmi/scapy_ipmi/commands.py tests/unit/test_channel_access.py
git commit -m "feat(proto): add Get Channel Access (0x41) request/response classes"
```

---

### Task 2: Decode helpers (user-access byte, channel-access resp, priv/mode maps)

**Files:**
- Create: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Produces:
  - `PRIV_NAME: dict[int,str]` (1→"callback" … 4→"administrator", 5→"oem", 0x0F→"no-access")
  - `ACCESS_MODE: dict[int,str]` (0→"disabled",1→"pre-boot-only",2→"always-available",3→"shared")
  - `decode_user_access(b:int) -> dict` → `{"priv","priv_raw","callin","link_auth","ipmi_msg"}`
  - `decode_channel_access(resp) -> dict` → `{"priv_limit","priv_limit_raw","access_mode","per_msg_auth","user_level_auth","alerting"}` (positive booleans: True = enabled)

Bit layout (IPMI 2.0 §22.27 Get User Access resp access byte, symmetric with §22.26 Set): `[6]`=user-restricted-to-callback (callin), `[5]`=link-auth-enabled, `[4]`=ipmi-messaging-enabled, `[3:0]`=privilege limit.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_user_matrix.py
from zipmi.cli.user_matrix import (
    decode_user_access, decode_channel_access, PRIV_NAME, ACCESS_MODE,
)
from zipmi.scapy_ipmi.commands import GetChannelAccessResp


def test_decode_user_access_admin_all_flags():
    # 0x54 = bit6(callin)+bit4(ipmi_msg)+priv 4 : 0101_0100
    d = decode_user_access(0x54)
    assert d["priv"] == "administrator"
    assert d["priv_raw"] == 4
    assert d["callin"] is True
    assert d["link_auth"] is False
    assert d["ipmi_msg"] is True


def test_decode_user_access_operator_linkauth():
    # 0x23 = bit5(link_auth)+priv 3 : 0010_0011
    d = decode_user_access(0x23)
    assert d["priv"] == "operator"
    assert d["link_auth"] is True
    assert d["callin"] is False
    assert d["ipmi_msg"] is False


def test_decode_channel_access_positives_and_mode():
    # access_byte 0x22: mode 2 (always-available), bit5 set = per-msg-auth DISABLED
    # priv_byte 0x03 = operator
    r = GetChannelAccessResp(bytes([0x00, 0x22, 0x03]))
    d = decode_channel_access(r)
    assert d["access_mode"] == "always-available"
    assert d["priv_limit"] == "operator"
    assert d["priv_limit_raw"] == 3
    assert d["per_msg_auth"] is False      # bit set = disabled → False
    assert d["user_level_auth"] is True    # bit4 clear = enabled
    assert d["alerting"] is True           # bit6 clear = enabled
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'zipmi.cli.user_matrix'`

- [ ] **Step 3: Write minimal implementation**

```python
# zipmi/cli/user_matrix.py
"""
zipmi.cli.user_matrix — full user × channel privilege/auth/cipher enumeration.

WHAT   Read-only, single-session enumeration of every user's access on every
       populated channel, plus per-channel access ceiling (Get Channel Access),
       auth capabilities (Get Channel Auth Caps), and cipher suites. Emits an
       information-first dict → human table or JSON. Optional passive findings.
WHY    Identity is global but access is per-channel with two stacking ceilings;
       the flat `user list` (single channel) cannot show the real grid. Modern
       successor to ~/bin/mega_chan.py (2014).
"""
from __future__ import annotations

PRIV_NAME: dict[int, str] = {
    0x01: "callback", 0x02: "user", 0x03: "operator",
    0x04: "administrator", 0x05: "oem", 0x0F: "no-access",
}

ACCESS_MODE: dict[int, str] = {
    0: "disabled", 1: "pre-boot-only", 2: "always-available", 3: "shared",
}


def decode_user_access(b: int) -> dict:
    """Get User Access response access byte (IPMI 2.0 §22.27)."""
    return {
        "priv": PRIV_NAME.get(b & 0x0F, f"raw-0x{b & 0x0F:x}"),
        "priv_raw": b & 0x0F,
        "callin": bool(b & 0x40),        # bit 6: restricted to callback
        "link_auth": bool(b & 0x20),     # bit 5
        "ipmi_msg": bool(b & 0x10),      # bit 4
    }


def decode_channel_access(resp) -> dict:
    """Get Channel Access response (IPMI 2.0 §22.23). The three 'disabled'
    bits are inverted here into positive 'enabled' booleans."""
    a = int(resp.access_byte)
    return {
        "priv_limit": PRIV_NAME.get(resp.priv_byte & 0x0F, f"raw-0x{resp.priv_byte & 0x0F:x}"),
        "priv_limit_raw": resp.priv_byte & 0x0F,
        "access_mode": ACCESS_MODE.get(a & 0x07, f"raw-{a & 0x07}"),
        "alerting": not (a & 0x40),          # bit6 set = disabled
        "per_msg_auth": not (a & 0x20),      # bit5 set = disabled
        "user_level_auth": not (a & 0x10),   # bit4 set = disabled
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): user-access + channel-access decode helpers"
```

---

### Task 3: `nv_delta` — present vs non-volatile channel-access diff

**Files:**
- Modify: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Produces: `nv_delta(present:dict, nonvol:dict) -> dict` — for each key whose value differs, `{key: {"present":..., "nonvolatile":...}}`; empty dict if identical.

- [ ] **Step 1: Write the failing test**

```python
def test_nv_delta_reports_only_differences():
    from zipmi.cli.user_matrix import nv_delta
    present = {"priv_limit": "operator", "access_mode": "always-available"}
    nonvol  = {"priv_limit": "administrator", "access_mode": "always-available"}
    assert nv_delta(present, nonvol) == {
        "priv_limit": {"present": "operator", "nonvolatile": "administrator"}
    }


def test_nv_delta_empty_when_identical():
    from zipmi.cli.user_matrix import nv_delta
    same = {"priv_limit": "administrator", "access_mode": "shared"}
    assert nv_delta(same, dict(same)) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k nv_delta -v`
Expected: FAIL with `ImportError: cannot import name 'nv_delta'`

- [ ] **Step 3: Write minimal implementation**

Append to `zipmi/cli/user_matrix.py`:

```python
def nv_delta(present: dict, nonvol: dict) -> dict:
    """Fields where the present (volatile) copy differs from non-volatile.
    Compares only keys common to both, ignoring raw-int companions."""
    out = {}
    for k in present:
        if k.endswith("_raw"):
            continue
        if k in nonvol and present[k] != nonvol[k]:
            out[k] = {"present": present[k], "nonvolatile": nonvol[k]}
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k nv_delta -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): nv_delta present-vs-nonvolatile channel diff"
```

---

### Task 4: `decode_auth_caps` — auth capabilities byte decode

**Files:**
- Modify: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Produces: `decode_auth_caps(resp) -> dict` from a `GetChanAuthCapsResp` → `{"ipmi20","auth_types":[...],"anon_login","null_user","non_null_user","per_msg_auth","user_level_auth"}`.

Bit layout (from `GetChanAuthCapsResp` in commands.py): `auth_type_support` — bit7 IPMI2.0, bit4 straight-pw, bit2 MD5, bit1 MD2, bit0 none. `status` — bit5 anon-login, bit4 null-user, bit3 non-null-user, bit2 per-msg-auth-disabled, bit1 user-level-auth-disabled.

- [ ] **Step 1: Write the failing test**

```python
def test_decode_auth_caps_md5_ipmi20_nonnull():
    from zipmi.cli.user_matrix import decode_auth_caps
    from zipmi.scapy_ipmi.commands import GetChanAuthCapsResp
    # auth_type_support 0x84 = bit7(ipmi2.0)+bit2(md5); status 0x08 = bit3 non-null
    r = GetChanAuthCapsResp(bytes([0x00, 0x01, 0x84, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]))
    d = decode_auth_caps(r)
    assert d["ipmi20"] is True
    assert "md5" in d["auth_types"]
    assert "none" not in d["auth_types"]
    assert d["non_null_user"] is True
    assert d["anon_login"] is False


def test_decode_auth_caps_flags_none_and_anon():
    from zipmi.cli.user_matrix import decode_auth_caps
    from zipmi.scapy_ipmi.commands import GetChanAuthCapsResp
    # auth 0x01 = none; status 0x20 = anon-login
    r = GetChanAuthCapsResp(bytes([0x00, 0x01, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]))
    d = decode_auth_caps(r)
    assert "none" in d["auth_types"]
    assert d["anon_login"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k auth_caps -v`
Expected: FAIL with `ImportError: cannot import name 'decode_auth_caps'`

- [ ] **Step 3: Write minimal implementation**

Append to `zipmi/cli/user_matrix.py`:

```python
_AUTH_BITS = [(0x10, "straight-pw"), (0x04, "md5"), (0x02, "md2"), (0x01, "none")]


def decode_auth_caps(resp) -> dict:
    """Get Channel Auth Caps response (IPMI 2.0 §22.13)."""
    ats = int(resp.auth_type_support)
    st = int(resp.status)
    return {
        "ipmi20": bool(ats & 0x80),
        "auth_types": [name for bit, name in _AUTH_BITS if ats & bit],
        "anon_login": bool(st & 0x20),
        "null_user": bool(st & 0x10),
        "non_null_user": bool(st & 0x08),
        "per_msg_auth": not (st & 0x04),      # bit set = disabled
        "user_level_auth": not (st & 0x02),   # bit set = disabled
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k auth_caps -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): decode_auth_caps helper"
```

---

### Task 5: `build_matrix` — the one-session enumeration (against an injected sender)

**Files:**
- Modify: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Consumes: a `sender` object exposing `send_cmd(netfn, cmd, req_packet) -> resp_packet` and `send_raw(netfn, cmd, bytes) -> (cc, data)` (the real `Session` satisfies this; tests pass a fake).
- Produces: `build_matrix(sender, target:str, *, include_empty=False, per_priv=False) -> dict` — the JSON-shaped dict from the spec (`target`, `max_user_count`, `enabled_user_count`, `channels`, `users`, `findings:[]`). Per-cell exceptions become `"err:<detail>"` string values.

Uses existing classes: `GetChannelInfoReq(channel=n)`, `GetChannelAccessReq(channel=n, access_type=...)`, `GetChanAuthCapsReq(v20_ext=1, channel=n, max_priv=p)`, `GetUserAccessReq(channel=n, user_id=u)`, `GetUserNameReq(user_id=u)`; cipher suites via `send_raw(0x06, 0x54, bytes([n, 0x00, 0x80]))` + `bmc_id.parse_cipher_list`.

- [ ] **Step 1: Write the failing test**

```python
def test_build_matrix_one_channel_two_users():
    from zipmi.cli.user_matrix import build_matrix
    from zipmi.scapy_ipmi.commands import (
        GetChannelInfoResp, GetChannelAccessResp, GetChanAuthCapsResp,
        GetUserAccessResp, GetUserNameResp,
    )

    class FakeSender:
        """Answers only channel 1; all other channels raise (unpopulated)."""
        def send_cmd(self, netfn, cmd, req):
            ch = getattr(req, "channel", None)
            uid = getattr(req, "user_id", None)
            if cmd == 0x42:                      # Get Channel Info
                if ch != 1:
                    raise RuntimeError("cc=0xcc")
                return GetChannelInfoResp(bytes([0x00, 0x01, 0x04, 0x01, 0x80,
                                                 0x00, 0x00, 0x00, 0x00, 0x00]))
            if cmd == 0x41:                      # Get Channel Access (vol/nv)
                # present: priv operator(3); nonvol: admin(4)
                pv = 0x03 if req.access_type == 0b10 else 0x04
                return GetChannelAccessResp(bytes([0x00, 0x02, pv]))
            if cmd == 0x38:                      # Auth caps
                return GetChanAuthCapsResp(bytes([0x00, 0x01, 0x84, 0x08,
                                                  0, 0, 0, 0, 0]))
            if cmd == 0x44:                      # Get User Access
                if uid == 1:  # discovery: max_user_count=2, enabled=2
                    return GetUserAccessResp(bytes([0x00, 0x02, 0x02, 0x00, 0x54]))
                acc = 0x54 if uid == 2 else 0x23   # u2 admin, u3 operator
                return GetUserAccessResp(bytes([0x00, 0x02, 0x02, 0x00, acc]))
            if cmd == 0x46:                      # Get User Name
                name = b"root".ljust(16, b"\x00") if uid == 2 else b"admin".ljust(16, b"\x00")
                return GetUserNameResp(bytes([0x00]) + name)
            raise AssertionError(f"unexpected cmd 0x{cmd:02x}")

        def send_raw(self, netfn, cmd, payload):
            if cmd == 0x54:                      # cipher suites: channel + IDs 3,17
                return 0x00, bytes([payload[0], 0x03, 0x11])
            raise AssertionError

    m = build_matrix(FakeSender(), "10.0.0.1")
    assert m["target"] == "10.0.0.1"
    assert m["max_user_count"] == 2
    assert set(m["channels"].keys()) == {"1"}         # only populated
    ch1 = m["channels"]["1"]
    assert ch1["medium"] == "802.3 LAN"
    assert ch1["access"]["present"]["priv_limit"] == "operator"
    assert ch1["access"]["nv_delta"]["priv_limit"] == {
        "present": "operator", "nonvolatile": "administrator"}
    assert ch1["cipher_suites"] == [3, 17]
    assert m["users"]["2"]["name"] == "root"
    assert m["users"]["2"]["access"]["1"]["priv"] == "administrator"
    assert m["users"]["3"]["access"]["1"]["priv"] == "operator"
    assert m["findings"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k build_matrix -v`
Expected: FAIL with `ImportError: cannot import name 'build_matrix'`

- [ ] **Step 3: Write minimal implementation**

Append to `zipmi/cli/user_matrix.py` (add these imports at the top of the file first):

```python
from ..scapy_ipmi.commands import (
    GetChannelInfoReq, GetChannelAccessReq, GetChanAuthCapsReq,
    GetUserAccessReq, GetUserNameReq,
)
from . import bmc_id
```

Body:

```python
# imported lazily inside functions to avoid a heavy import at module load
_CHANNEL_MEDIUM_FALLBACK = "unknown"


def _err(exc: Exception) -> str:
    msg = str(exc)
    return f"err:{msg or exc.__class__.__name__}"


def _channel_info(sender, n: int) -> dict | None:
    """Get Channel Info for channel n; None if unpopulated (any error)."""
    from .zipmi import CHANNEL_MEDIUM, CHANNEL_PROTOCOL
    try:
        r = sender.send_cmd(0x06, 0x42, GetChannelInfoReq(channel=n))
    except Exception:
        return None
    if int(r.comp_code) != 0x00:
        return None
    sess = int(r.session_support) >> 6
    sess_name = {0: "sessionless", 1: "single-session",
                 2: "multi-session", 3: "sessionless+session"}.get(sess, "unknown")
    return {
        "medium": CHANNEL_MEDIUM.get(int(r.medium), _CHANNEL_MEDIUM_FALLBACK),
        "medium_raw": int(r.medium),
        "protocol": CHANNEL_PROTOCOL.get(int(r.protocol), _CHANNEL_MEDIUM_FALLBACK),
        "protocol_raw": int(r.protocol),
        "session_support": sess_name,
        "vendor_iana": int.from_bytes(bytes(r.oem_iana), "little"),
    }


def _channel_access(sender, n: int) -> dict:
    def one(access_type):
        r = sender.send_cmd(0x06, 0x41, GetChannelAccessReq(channel=n, access_type=access_type))
        if int(r.comp_code) != 0x00:
            raise RuntimeError(f"cc=0x{int(r.comp_code):02x}")
        return decode_channel_access(r)
    try:
        present = one(0b10)
        nonvol = one(0b01)
    except Exception as e:
        return {"error": _err(e)}
    out = {"present": present, "nonvolatile": nonvol}
    delta = nv_delta(present, nonvol)
    if delta:
        out["nv_delta"] = delta
    return out


def _auth_caps(sender, n: int, per_priv: bool) -> dict:
    def one(p):
        r = sender.send_cmd(0x06, 0x38, GetChanAuthCapsReq(v20_ext=1, channel=n, max_priv=p))
        if int(r.comp_code) != 0x00:
            raise RuntimeError(f"cc=0x{int(r.comp_code):02x}")
        return decode_auth_caps(r)
    if per_priv:
        out = {}
        for p, name in ((1, "callback"), (2, "user"), (3, "operator"),
                        (4, "administrator"), (5, "oem")):
            try:
                out[name] = one(p)
            except Exception as e:
                out[name] = {"error": _err(e)}
        return {"by_priv": out}
    try:
        d = one(4)
        d["at_priv"] = "administrator"
        return d
    except Exception as e:
        return {"error": _err(e)}


def _cipher_suites(sender, n: int) -> list | str:
    try:
        cc, data = sender.send_raw(0x06, 0x54, bytes([n, 0x00, 0x80]))
        if cc != 0x00:
            return _err(RuntimeError(f"cc=0x{cc:02x}"))
        return bmc_id.parse_cipher_list(data[1:])
    except Exception as e:
        return _err(e)


def build_matrix(sender, target: str, *, include_empty=False, per_priv=False) -> dict:
    channels: dict[str, dict] = {}
    for n in range(0x00, 0x10):
        if n == 0x0E:                       # self-alias — skip
            continue
        info = _channel_info(sender, n)
        if info is None:
            if include_empty:
                channels[str(n)] = {"empty": True}
            continue
        info["access"] = _channel_access(sender, n)
        info["auth_caps"] = _auth_caps(sender, n, per_priv)
        info["cipher_suites"] = _cipher_suites(sender, n)
        channels[str(n)] = info

    populated = [int(k) for k, v in channels.items() if not v.get("empty")]

    # discover user count on the first populated channel (fallback 0xE)
    disc_ch = populated[0] if populated else 0x0E
    try:
        u1 = sender.send_cmd(0x06, 0x44, GetUserAccessReq(channel=disc_ch, user_id=1))
        max_users = int(u1.max_user_count) & 0x3F
        enabled = int(u1.enabled_user_count) & 0x3F
    except Exception:
        max_users, enabled = 0, 0

    users: dict[str, dict] = {}
    for uid in range(1, max_users + 1):
        try:
            un = sender.send_cmd(0x06, 0x46, GetUserNameReq(user_id=uid))
            name = bytes(un.user_name).rstrip(b"\x00").decode("utf-8", "replace")
        except Exception as e:
            name = _err(e)
        acc: dict[str, dict | str] = {}
        for n in populated:
            try:
                ua = sender.send_cmd(0x06, 0x44, GetUserAccessReq(channel=n, user_id=uid))
                if int(ua.comp_code) != 0x00:
                    acc[str(n)] = _err(RuntimeError(f"cc=0x{int(ua.comp_code):02x}"))
                else:
                    acc[str(n)] = decode_user_access(int(ua.user_access))
            except Exception as e:
                acc[str(n)] = _err(e)
        users[str(uid)] = {"name": name, "access": acc}

    return {
        "target": target,
        "max_user_count": max_users,
        "enabled_user_count": enabled,
        "channels": channels,
        "users": users,
        "findings": [],
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k build_matrix -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): build_matrix one-session enumeration"
```

---

### Task 6: `evaluate_findings` — passive derived posture flags

**Files:**
- Modify: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Produces: `evaluate_findings(matrix:dict) -> list[dict]` — each `{"severity","channel","issue"}` (and `"user"` where applicable). Passive: reads only the already-built matrix. Rules: cipher-0 advertised (suite `0` in `cipher_suites`); `anon_login`/`null_user` true; `auth_types` contains `"none"`; `per_msg_auth` or `user_level_auth` False (disabled).

- [ ] **Step 1: Write the failing test**

```python
def test_evaluate_findings_flags_cipher0_and_anon():
    from zipmi.cli.user_matrix import evaluate_findings
    matrix = {
        "channels": {
            "1": {
                "cipher_suites": [0, 3, 17],
                "auth_caps": {"anon_login": True, "null_user": False,
                              "auth_types": ["md5"], "per_msg_auth": True,
                              "user_level_auth": True},
            }
        },
        "users": {},
    }
    issues = {f["issue"] for f in evaluate_findings(matrix)}
    assert "cipher-0 advertised" in issues
    assert "anonymous login enabled" in issues


def test_evaluate_findings_clean_channel_empty():
    from zipmi.cli.user_matrix import evaluate_findings
    matrix = {
        "channels": {
            "1": {
                "cipher_suites": [3, 17],
                "auth_caps": {"anon_login": False, "null_user": False,
                              "auth_types": ["md5"], "per_msg_auth": True,
                              "user_level_auth": True},
            }
        },
        "users": {},
    }
    assert evaluate_findings(matrix) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k evaluate_findings -v`
Expected: FAIL with `ImportError: cannot import name 'evaluate_findings'`

- [ ] **Step 3: Write minimal implementation**

Append to `zipmi/cli/user_matrix.py`:

```python
def evaluate_findings(matrix: dict) -> list[dict]:
    """Passive posture flags derived from an already-built matrix."""
    out: list[dict] = []
    for ch, info in matrix.get("channels", {}).items():
        if info.get("empty"):
            continue
        chn = int(ch)
        suites = info.get("cipher_suites")
        if isinstance(suites, list) and 0 in suites:
            out.append({"severity": "high", "channel": chn, "issue": "cipher-0 advertised"})
        caps = info.get("auth_caps", {})
        if caps.get("anon_login"):
            out.append({"severity": "high", "channel": chn, "issue": "anonymous login enabled"})
        if caps.get("null_user"):
            out.append({"severity": "med", "channel": chn, "issue": "null username enabled"})
        if "none" in (caps.get("auth_types") or []):
            out.append({"severity": "high", "channel": chn, "issue": "auth type 'none' offered"})
        if caps.get("per_msg_auth") is False:
            out.append({"severity": "med", "channel": chn, "issue": "per-message auth disabled"})
        if caps.get("user_level_auth") is False:
            out.append({"severity": "low", "channel": chn, "issue": "user-level auth disabled"})
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k evaluate_findings -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): passive evaluate_findings posture flags"
```

---

### Task 7: `render_table` — human output

**Files:**
- Modify: `zipmi/cli/user_matrix.py`
- Test: `tests/unit/test_user_matrix.py`

**Interfaces:**
- Produces: `render_table(matrix:dict) -> str`. Prints a channel header line (num · medium · session · present ceiling), a per-user row with a compact cell per populated channel (`priv` + flag letters `E`nabled-msg/`la`ink-auth/`ci`allin), a legend, and — if any channel carries `nv_delta` — a `Δ` note line per delta. Cells that are `err:*` strings print verbatim.

- [ ] **Step 1: Write the failing test**

```python
def test_render_table_contains_users_channels_and_delta():
    from zipmi.cli.user_matrix import render_table
    matrix = {
        "target": "10.0.0.1", "max_user_count": 1, "enabled_user_count": 1,
        "channels": {"1": {
            "medium": "802.3 LAN", "session_support": "multi-session",
            "access": {"present": {"priv_limit": "operator"},
                       "nonvolatile": {"priv_limit": "administrator"},
                       "nv_delta": {"priv_limit": {"present": "operator",
                                                   "nonvolatile": "administrator"}}},
            "cipher_suites": [3, 17], "auth_caps": {"auth_types": ["md5"]},
        }},
        "users": {"2": {"name": "root",
                        "access": {"1": {"priv": "administrator", "ipmi_msg": True,
                                         "link_auth": True, "callin": False}}}},
        "findings": [],
    }
    out = render_table(matrix)
    assert "root" in out
    assert "802.3 LAN" in out
    assert "administrator" in out or "admin" in out
    assert "Δ" in out and "operator" in out    # delta note rendered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k render_table -v`
Expected: FAIL with `ImportError: cannot import name 'render_table'`

- [ ] **Step 3: Write minimal implementation**

Append to `zipmi/cli/user_matrix.py`:

```python
def _cell(acc) -> str:
    if isinstance(acc, str):                 # err:*
        return acc
    flags = "".join(f for f, on in (("E", acc.get("ipmi_msg")),
                                    ("la", acc.get("link_auth")),
                                    ("ci", acc.get("callin"))) if on)
    return f"{acc.get('priv', '?')} {flags}".rstrip()


def render_table(matrix: dict) -> str:
    chans = [k for k, v in matrix["channels"].items() if not v.get("empty")]
    lines = [f"target {matrix['target']}  "
             f"users {matrix['enabled_user_count']}/{matrix['max_user_count']}", ""]
    # channel header
    for ch in chans:
        info = matrix["channels"][ch]
        ceil = info.get("access", {}).get("present", {}).get("priv_limit", "?")
        lines.append(f"  ch{ch}: {info.get('medium','?')} / "
                     f"{info.get('session_support','?')} / limit={ceil}")
    lines.append("")
    lines.append(f"{'user':16}  " + "  ".join(f"ch{c}" for c in chans))
    for uid, u in matrix["users"].items():
        cells = "  ".join(_cell(u["access"].get(c, "—")) for c in chans)
        lines.append(f"{uid:>2} {u['name']:13}  {cells}")
    # delta notes
    for ch in chans:
        delta = matrix["channels"][ch].get("access", {}).get("nv_delta")
        if delta:
            for field, d in delta.items():
                lines.append(f"Δ ch{ch}: {field} present={d['present']} "
                             f"non-volatile={d['nonvolatile']} (pending/override)")
    lines.append("")
    lines.append("legend: cell = <priv> [E=ipmi-msg la=link-auth ci=callin]; "
                 "Δ = present≠non-volatile")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_user_matrix.py -k render_table -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/user_matrix.py tests/unit/test_user_matrix.py
git commit -m "feat(user-matrix): render_table human output"
```

---

### Task 8: CLI wiring — `user-matrix list` verb + `cmd_user_matrix_list`

**Files:**
- Modify: `zipmi/cli/zipmi.py` (add `cmd_user_matrix_list` near the other user cmds ~line 970; add subparser near the `user` verb wiring ~line 2874; import the module)
- Test: `tests/unit/test_flag_position.py` (parse wiring) + `tests/integration/test_user_matrix_cli.py`

**Interfaces:**
- Consumes: `user_matrix.build_matrix`, `render_table`, `evaluate_findings`; `_open_session`.
- Produces: `cmd_user_matrix_list(args) -> int`. Reads `args.json`, `args.all`, `args.per_priv`, `args.findings`. Emits JSON to stdout with `--json`; else the table. Findings appended to `matrix["findings"]` when `args.findings`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_flag_position.py  (append)
def test_user_matrix_list_parses():
    ns = parse_cli(["user-matrix", "list", "--json", "--all"])
    assert ns.func.__name__ == "cmd_user_matrix_list"
    assert ns.json is True
    assert ns.all is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_flag_position.py -k user_matrix -v`
Expected: FAIL (`argument ... invalid choice: 'user-matrix'` → SystemExit)

- [ ] **Step 3: Write minimal implementation**

Add the import near the top of `zipmi/cli/zipmi.py` (with the other `from . import` lines):

```python
from . import user_matrix as _user_matrix
```

Add the command function (near `cmd_user_priv`):

```python
def cmd_user_matrix_list(args: argparse.Namespace) -> int:
    """Full user × channel privilege/auth/cipher matrix (read-only, one session)."""
    import json
    with _open_session(args) as s:
        matrix = _user_matrix.build_matrix(
            s, _require_host(args),
            include_empty=getattr(args, "all", False),
            per_priv=getattr(args, "per_priv", False),
        )
    if getattr(args, "findings", False):
        matrix["findings"] = _user_matrix.evaluate_findings(matrix)
    if getattr(args, "json", False):
        print(json.dumps(matrix, indent=2))
    else:
        print(_user_matrix.render_table(matrix))
        for f in matrix["findings"]:
            print(f"  ! [{f['severity']}] ch{f['channel']}: {f['issue']}",
                  file=sys.stderr)
    return 0
```

Add subparser wiring (near the `user` verb block ~line 2874):

```python
    umx = sub.add_parser("user-matrix", help="full user × channel privilege matrix")
    umx_sub = umx.add_subparsers(dest="action", required=True)
    umx_list = umx_sub.add_parser("list", help="enumerate the whole grid (read-only)")
    umx_list.add_argument("--json", action="store_true", help="emit JSON to stdout")
    umx_list.add_argument("--all", action="store_true",
                          help="include empty/unimplemented channels")
    umx_list.add_argument("--per-priv", dest="per_priv", action="store_true",
                          help="sweep auth-caps at all 5 privilege levels")
    umx_list.add_argument("--findings", action="store_true",
                          help="also emit derived posture flags")
    umx_list.set_defaults(func=cmd_user_matrix_list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_flag_position.py -k user_matrix -v`
Expected: PASS

- [ ] **Step 5: Integration test against a vbmc persona**

```python
# tests/integration/test_user_matrix_cli.py
import json, subprocess, sys, time, socket


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def test_user_matrix_json_against_vbmc(tmp_path):
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, "-m", "zipmi.cli.zipmi", "vbmc", "serve",
         "--vpersona", "generic", "--vport", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        out = subprocess.run(
            [sys.executable, "-m", "zipmi.cli.zipmi", "-H", "127.0.0.1",
             "-p", str(port), "-U", "root", "-P", "calvin",
             "user-matrix", "list", "--json"],
            capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout)
        assert data["target"] == "127.0.0.1"
        assert "channels" in data and "users" in data
        assert isinstance(data["findings"], list)
    finally:
        srv.terminate(); srv.wait(timeout=5)
```

Run: `python3 -m pytest tests/integration/test_user_matrix_cli.py -v`
Expected: PASS (adjust `--vpersona generic` to an existing persona if the name differs — check `zipmi vbmc serve --help`).

- [ ] **Step 6: Commit**

```bash
git add zipmi/cli/zipmi.py tests/unit/test_flag_position.py tests/integration/test_user_matrix_cli.py
git commit -m "feat(cli): user-matrix list verb (--json/--all/--per-priv/--findings)"
```

---

### Task 9: `scan all` → full grid (findings on, graceful sessionless)

**Files:**
- Modify: `zipmi/cli/zipmi.py` (`cmd_scan_all` ~line 2354)
- Test: `tests/integration/test_user_matrix_cli.py`

**Interfaces:**
- Consumes: `cmd_user_matrix_list`. `scan all` runs `asf-ping` then the full grid with findings forced on.

- [ ] **Step 1: Write the failing test**

```python
def test_scan_all_runs_full_grid_with_findings(tmp_path):
    import json, subprocess, sys, time, socket
    def _free_port():
        s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
        return p
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, "-m", "zipmi.cli.zipmi", "vbmc", "serve",
         "--vpersona", "generic", "--vport", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        out = subprocess.run(
            [sys.executable, "-m", "zipmi.cli.zipmi", "-H", "127.0.0.1",
             "-p", str(port), "-U", "root", "-P", "calvin",
             "scan", "all", "--json"],
            capture_output=True, text=True, timeout=30)
        # scan all emits the matrix JSON (with findings key) as its last block
        assert '"channels"' in out.stdout and '"findings"' in out.stdout
    finally:
        srv.terminate(); srv.wait(timeout=5)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/integration/test_user_matrix_cli.py -k scan_all -v`
Expected: FAIL (current `scan all` = asf-ping+auth-caps, no matrix JSON)

- [ ] **Step 3: Write minimal implementation**

Replace `cmd_scan_all` in `zipmi/cli/zipmi.py`:

```python
def cmd_scan_all(args: argparse.Namespace) -> int:
    rc = 0
    rc |= cmd_scan_asf_ping(args)
    # full user × channel grid, findings forced on (scan = posture probe)
    args.findings = True
    for attr, default in (("json", False), ("all", False), ("per_priv", False)):
        if not hasattr(args, attr):
            setattr(args, attr, default)
    rc |= cmd_user_matrix_list(args)
    return rc
```

Add `--json` to the `scan all` subparser if it lacks it (check the `scan` wiring ~line 3067; the omnibus needs `--json` to pass through). If the shared `scan` parser has no `--json`, add:

```python
    scan_all_p.add_argument("--json", action="store_true",
                            help="emit the full-grid matrix as JSON")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/integration/test_user_matrix_cli.py -k scan_all -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add zipmi/cli/zipmi.py tests/integration/test_user_matrix_cli.py
git commit -m "feat(scan): scan all now runs the full user-matrix grid (findings on)"
```

---

### Task 10: Docs — README verb + command-table.md coverage

**Files:**
- Modify: `README.md` (the `zipmi verbs` list + a short user-matrix example)
- Modify: `docs/command-table.md` (mark `41h Get Channel Access` → ✓)

- [ ] **Step 1: Update README** — add to the verb list and an example:

````markdown
user-matrix list [--json] [--all] [--per-priv] [--findings]
                 # full user × channel privilege/auth/cipher grid (read-only)
````

```bash
# audit the whole grid; JSON for tooling
zipmi -H <bmc> user-matrix list
zipmi -H <bmc> user-matrix list --json | jq '.channels'
```

- [ ] **Step 2: Update `docs/command-table.md`** — change the `41h Get Channel Access` row zipmi column from `✗` to `✓`.

- [ ] **Step 3: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: PASS (all prior + new tests).

- [ ] **Step 4: Commit**

```bash
git add README.md docs/command-table.md
git commit -m "docs(user-matrix): README verb + command-table 0x41 coverage"
```

---

## Notes for the implementer

- **Verify one bit layout against a live box when available:** `decode_user_access` uses `[6]`=callin, `[5]`=link-auth, `[4]`=ipmi-msg, `[3:0]`=priv (IPMI 2.0 §22.27, symmetric with the Set User Access encoding in `cmd_user_priv`). If a zoo box is reachable, cross-check one real `user_access` byte; the unit test pins the decode either way.
- **`--per-priv` default off** and **`--findings` default off** are DoS/information-first guards — do not flip.
- **vbmc persona name:** Task 8/9 integration tests assume a `generic` persona; confirm via `zipmi vbmc serve --help` and adjust if the registry uses a different name (e.g. `dell_idrac6`).
- **Early output checkpoint (user request):** after Task 7, run `render_table`/JSON against a vbmc persona and show the user real output before Task 8/9 lock the CLI surface.
