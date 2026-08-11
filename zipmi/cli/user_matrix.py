"""
zipmi.cli.user_matrix — full user × channel privilege/auth/cipher enumeration.

WHAT   Read-only, single-session enumeration of every user's access on every
       populated channel, plus per-channel access ceiling (Get Channel Access),
       auth capabilities (Get Channel Auth Caps), and cipher suites. Emits an
       information-first dict → human table or JSON. Optional passive findings.
WHY    Identity is global but access is per-channel with two stacking ceilings;
       the flat `user list` (single channel) cannot show the real grid. Modern
       successor to ~/bin/mega_chan.py (2014).

Bit layouts: Get User Access response access byte (IPMI 2.0 §22.27, symmetric
with §22.26 Set): [6]=restricted-to-callback (callin), [5]=link-auth-enabled,
[4]=ipmi-messaging-enabled, [3:0]=privilege limit.
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


# -- one-session enumeration -------------------------------------------------

from ..scapy_ipmi.commands import (          # noqa: E402
    GetChannelInfoReq, GetChannelAccessReq, GetChanAuthCapsReq,
    GetUserAccessReq, GetUserNameReq, SetSessionPrivLevelReq,
)
from . import bmc_id                          # noqa: E402


def _err(exc: Exception) -> str:
    return f"err:{exc or exc.__class__.__name__}"


def _channel_info(sender, n: int) -> dict | None:
    """Get Channel Info for channel n; None if unpopulated (any error/cc!=0)."""
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
        "medium": CHANNEL_MEDIUM.get(int(r.medium), "unknown"),
        "medium_raw": int(r.medium),
        "protocol": CHANNEL_PROTOCOL.get(int(r.protocol), "unknown"),
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


def _cipher_suites(sender, n: int):
    """Enumerate advertised cipher suites via Get Channel Cipher Suites (0x54),
    looping list indices until a short chunk. Reuses the record decoder that the
    scan verb uses, so the two agree."""
    acc = b""
    for idx in range(0x40):
        try:
            cc, data = sender.send_raw(0x06, 0x54, bytes([n, 0x00, 0x80 | idx]))
        except Exception as e:
            if idx == 0:
                return _err(e)
            break
        if cc != 0x00:
            if idx == 0:
                return _err(RuntimeError(f"cc=0x{cc:02x}"))
            break
        chunk = data[1:]                 # strip leading channel byte
        acc += chunk
        if len(chunk) < 16:
            break
    return [r["id"] for r in bmc_id.parse_cipher_suite_records(acc)]


def _lan_param(sender, ch: int, param: int) -> bytes | None:
    """One Get LAN Config Parameters value (Transport 0x0C/0x02); config bytes
    with the leading parameter-revision byte stripped. None on error."""
    try:
        cc, data = sender.send_raw(0x0C, 0x02, bytes([ch, param, 0, 0]))
    except Exception:
        return None
    if cc != 0x00 or len(data) < 2:
        return None
    return data[1:]                       # drop param-revision byte


def _medium_detail(sender, ch: int, medium_raw: int) -> dict:
    """Substrate-specific config, dispatched by medium — the analog of Get LAN
    Config for each wire. Best-effort; unreadable params are simply omitted."""
    try:
        if medium_raw in (0x04, 0x06):    # 802.3 LAN / other LAN
            out: dict = {}
            mac = _lan_param(sender, ch, 5)          # param 5 = MAC
            if mac and len(mac) >= 6:
                out["mac"] = ":".join(f"{b:02x}" for b in mac[:6])
            ip = _lan_param(sender, ch, 3)           # param 3 = IP address
            if ip and len(ip) >= 4:
                out["ip"] = ".".join(str(b) for b in ip[:4])
            src = _lan_param(sender, ch, 4)          # param 4 = IP address source
            if src:
                out["ip_source"] = {1: "static", 2: "dhcp", 3: "bios",
                                    4: "other"}.get(src[0], src[0])
            vlan = _lan_param(sender, ch, 20)        # param 20 = VLAN id
            if vlan and len(vlan) >= 2:
                v = vlan[0] | (vlan[1] << 8)
                out["vlan"] = (v & 0x0FFF) if (v & 0x8000) else None
            return out
        if medium_raw == 0x05:            # async serial/modem
            # Full Get Serial/Modem Config sweep — connection mode + every modem
            # string (init / dial / escape) and alert-destination config.
            from .serial_modem import serial_config_sweep
            params = serial_config_sweep(sender, ch)
            out = {"serial_params": params}
            # surface the juicy strings: init (10), dial command (13), and the
            # actual destination phone number(s) (21).
            for p in params:
                if p.get("ascii") and p["param"] in (10, 13, 21):
                    out.setdefault("strings", {})[p["name"]] = p["ascii"]
            return out
        if medium_raw == 0x0C:            # system interface (KCS/SMIC/BT)
            # Get System Interface Capabilities (App 0x06/0x57), SI type 1 = KCS.
            try:
                cc, data = sender.send_raw(0x06, 0x57, bytes([0x01]))
            except Exception as e:
                return {"error": _err(e)}
            if cc != 0x00:
                return {"error": f"si-caps cc=0x{cc:02x}"}
            return {"si_caps_raw": data.hex()}
    except Exception as e:
        return {"error": _err(e)}
    return {}


def _connected_channel(sender) -> int | None:
    """Resolve which channel our session is on: Get Channel Info(0xE), the
    'present channel' alias, returns its real number."""
    try:
        r = sender.send_cmd(0x06, 0x42, GetChannelInfoReq(channel=0x0E))
    except Exception:
        return None
    return int(r.channel) if int(r.comp_code) == 0x00 else None


def build_matrix(sender, target: str, *, include_empty=False, per_priv=False,
                 bridge=False, medium=False, raise_priv=True) -> dict:
    connected = _connected_channel(sender)

    # Raise our session to its granted maximum BEFORE walking the grid. Get User
    # Access (and channel/auth-caps reads) may require Operator/Administrator; a
    # session left at a low default operating priv would get cc=0xcc/0xd4 back and
    # MIS-report real access as "no access". Set Session Privilege Level (0x3B)
    # only raises within our own entitlement (grants min(user,channel,requested))
    # and only affects this ephemeral session — no persistent BMC change. The
    # granted level is also the authoritative effective ceiling on the connected
    # channel, recorded below. Best-effort: if 0x3B is rejected we walk as-is.
    effective_priv = None
    if raise_priv:
        for lvl in (0x04, 0x05):              # administrator, then oem
            try:
                r = sender.send_cmd(0x06, 0x3B, SetSessionPrivLevelReq(priv=lvl))
            except Exception:
                break
            if int(r.comp_code) != 0x00:      # requested exceeds ceiling → stop
                break
            effective_priv = int(r.priv) & 0x0F

    channels: dict[str, dict] = {}
    for n in range(0x00, 0x10):
        if n == 0x0E:                    # self-alias — skip
            continue
        info = _channel_info(sender, n)
        if info is None:
            if include_empty:
                channels[str(n)] = {"empty": True}
            continue
        info["access"] = _channel_access(sender, n)
        info["auth_caps"] = _auth_caps(sender, n, per_priv)
        info["cipher_suites"] = _cipher_suites(sender, n)
        if n == connected:
            info["connected"] = True
        if medium:
            info["medium_detail"] = _medium_detail(sender, n, info["medium_raw"])
        if bridge:                        # can the BMC bridge onto this channel?
            from .bridge import probe_bridge
            info["bridge"] = probe_bridge(sender, n)
        channels[str(n)] = info

    populated = [int(k) for k, v in channels.items() if not v.get("empty")]
    # Discover the user count on a channel that actually answers Get User Access.
    # 0xE = the present/connected channel (our session) is tried first; sessionless
    # channels like IPMB (0) and KCS reject the query, so never lead with populated[0].
    max_users, enabled = 0, 0
    for dch in [0x0E, *populated]:
        try:
            u1 = sender.send_cmd(0x06, 0x44, GetUserAccessReq(channel=dch, user_id=1))
        except Exception:
            continue
        if int(u1.comp_code) == 0x00 and (int(u1.max_user_count) & 0x3F):
            max_users = int(u1.max_user_count) & 0x3F
            enabled = int(u1.enabled_user_count) & 0x3F
            break

    # Classify each populated channel by how it ANSWERS Get User Access (0x44) —
    # measured, not assumed. Probe once per channel (channel-level property, not
    # per-user): cc=0x00 => per-user access is meaningful, query every user;
    # cc=0xcc ("invalid data field") => the BMC itself says the query is undefined
    # here (sessionless IPMB / system interface) → n/a, on evidence; any other cc
    # or transport error => unknown (we could not determine it).
    ua_support: dict[int, str] = {}
    for n in populated:
        try:
            p = sender.send_cmd(0x06, 0x44, GetUserAccessReq(channel=n, user_id=1))
            cc = int(p.comp_code)
            ua_support[n] = "yes" if cc == 0x00 else ("no" if cc == 0xCC else "unknown")
        except Exception:
            ua_support[n] = "unknown"
        channels[str(n)]["user_access_query"] = ua_support[n]

    users: dict[str, dict] = {}
    for uid in range(1, max_users + 1):
        try:
            un = sender.send_cmd(0x06, 0x46, GetUserNameReq(user_id=uid))
            name = bytes(un.user_name).rstrip(b"\x00").decode("utf-8", "replace")
        except Exception as e:
            name = _err(e)
        acc: dict[str, dict | str] = {}
        enabled = 0                           # Get User Access byte4[7:6]: 0=unspec
        for n in populated:                   #   1=enabled, 2=disabled (global/user)
            sup = ua_support[n]
            if sup == "no":                   # BMC returned cc=0xcc → n/a, evidenced
                acc[str(n)] = "n/a"
                continue
            if sup == "unknown":              # could not determine
                acc[str(n)] = "unknown"
                continue
            try:
                ua = sender.send_cmd(0x06, 0x44, GetUserAccessReq(channel=n, user_id=uid))
                if int(ua.comp_code) != 0x00:
                    acc[str(n)] = _err(RuntimeError(f"cc=0x{int(ua.comp_code):02x}"))
                else:
                    acc[str(n)] = decode_user_access(int(ua.user_access))
                    if not enabled:           # per-user enable is global; first wins
                        enabled = (int(ua.fixed_name_users) >> 6) & 0x3
            except Exception as e:
                acc[str(n)] = _err(e)
        users[str(uid)] = {"name": name, "access": acc, "enabled": enabled}

    # Record the granted ceiling on the connected channel (from the pre-walk raise).
    if effective_priv is not None and connected is not None and str(connected) in channels:
        channels[str(connected)]["effective_priv"] = PRIV_NAME.get(
            effective_priv, f"raw-0x{effective_priv:x}")

    return {
        "target": target,
        "max_user_count": max_users,
        "enabled_user_count": enabled,
        "channels": channels,
        "users": users,
        "findings": [],
    }


def evaluate_findings(matrix: dict) -> list[dict]:
    """Passive posture flags derived from an already-built matrix (no new sends)."""
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


_PRIV_CODE = {"callback": "C", "user": "U", "operator": "O",
              "administrator": "A", "oem": "M", "no-access": "x"}


def _cell(acc) -> str:
    """Compact grid code: priv letter + flag letters. "-"=n/a (sessionless),
    "x"=no-access, "!"=unexpected error, "?"=unknown priv nibble."""
    if isinstance(acc, str):
        if acc == "n/a":
            return "-"
        if acc == "unknown":
            return "?"
        if acc.startswith("err:"):
            return "!"
        return acc
    code = _PRIV_CODE.get(acc.get("priv"), "?")
    flags = "".join(f for f, on in (("I", acc.get("ipmi_msg")),
                                    ("L", acc.get("link_auth")),
                                    ("c", acc.get("callin"))) if on)
    return code + flags


def render_table(matrix: dict) -> str:
    chans = [k for k, v in matrix["channels"].items() if not v.get("empty")]
    lines = [f"target {matrix['target']}  "
             f"users {matrix['enabled_user_count']}/{matrix['max_user_count']}", ""]
    for ch in chans:
        info = matrix["channels"][ch]
        acc_info = info.get("access", {})
        if "present" in acc_info:                       # Get Channel Access answered
            ceil = acc_info["present"].get("priv_limit", "?")
        else:                                           # errored — mirror the cell semantics
            ceil = "n/a" if "cc=0xcc" in acc_info.get("error", "") else "?"
        br = info.get("bridge")
        brtag = ""
        if br is not None:
            brtag = ("  bridge:yes" if br.get("bridgeable")
                     else "  bridge:no" if br.get("bridgeable") is False
                     else "  bridge:?")
        conn = "  ← connected" if info.get("connected") else ""
        eff = f"  effective={info['effective_priv']}" if info.get("effective_priv") else ""
        lines.append(f"  ch{ch}: {info.get('medium','?')} / "
                     f"{info.get('session_support','?')} / limit={ceil}{brtag}{conn}{eff}")
        md = info.get("medium_detail") or {}
        bits = []
        if md.get("mac"):
            bits.append(f"mac={md['mac']}")
        if md.get("ip"):
            bits.append(f"ip={md['ip']}" + (f"/{md['ip_source']}" if md.get("ip_source") else ""))
        if md.get("vlan") is not None:
            bits.append(f"vlan={md['vlan']}")
        for name, s in (md.get("strings") or {}).items():
            bits.append(f"{name}={s}")     # modem init / dial strings
        if bits:
            lines.append(f"        └ {'  '.join(bits)}")
    lines.append("")
    # aligned user × channel grid with compact codes
    headers = [f"ch{c}" for c in chans]
    # Per IPMI 2.0: per-user privilege limits are OPTIONAL. Where the per-user
    # query is unavailable (n/a / unknown) but the channel HAS a known privilege
    # limit, that channel limit applies to every user — render it, marked '*'
    # (inherited), instead of leaving the cell blank.
    chan_code = {}
    for c in chans:
        pl = matrix["channels"][c].get("access", {}).get("present", {}).get("priv_limit")
        chan_code[c] = _PRIV_CODE.get(pl) if pl else None

    def gridcell(c, v):
        if isinstance(v, str) and v in ("n/a", "unknown") and chan_code.get(c):
            return chan_code[c] + "*"          # inherited from channel limit
        return _cell(v)

    _EN = {0: "?", 1: "y", 2: "n", 3: "?"}    # byte4[7:6] enable status
    grid = []
    for uid, u in matrix["users"].items():
        name = u["name"] or "<null>"          # zero-length username = the null/anon user
        en = _EN.get(u.get("enabled", 0), "?")
        grid.append((uid, name, en, [gridcell(c, u["access"].get(c, "unknown")) for c in chans]))
    widths = [len(h) for h in headers]
    for _, _, _, cells in grid:
        for i, c in enumerate(cells):
            widths[i] = max(widths[i], len(c))
    lines.append(f"{'user':16} en  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    for uid, name, en, cells in grid:
        lines.append(f"{uid:>2} {name:13} {en:2}  "
                     + "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)))
    for ch in chans:
        delta = matrix["channels"][ch].get("access", {}).get("nv_delta")
        if delta:
            for field, d in delta.items():
                lines.append(f"Δ ch{ch}: {field} present={d['present']} "
                             f"non-volatile={d['nonvolatile']} (pending/override)")
    lines.append("")
    lines.append("legend: priv  A=administrator O=operator U=user C=callback M=oem   "
                 "x=no-access  -=n/a(BMC cc=0xcc)  ?=unknown  *=channel-limit(per-user n/a)")
    lines.append("        flags I=ipmi-msg L=link-auth c=callin   Δ=present≠non-volatile")
    lines.append("        ←connected = channel this session rode in on   "
                 "<null> = zero-length (anonymous) username")
    lines.append("        en (global enable, Get User Access byte4[7:6]): y=enabled "
                 "n=disabled ?=BMC unspecified — count in header 'users e/max'")
    return "\n".join(lines)
