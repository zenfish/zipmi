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
