"""
zipmi.cli.serial_modem — Get/Set Serial/Modem Configuration (0x0C/0x11, 0x0C/0x10).

WHAT   (#1, read) Enumerate every serial/modem config parameter — connection
       mode, modem init/dial/escape/hangup strings, callback control, alert
       destinations and their dial numbers, community string. This is the deep
       recon for the serial substrate: is the channel wired to dial, and to
       what number.
       (#2, write) The dial-out primitive: Set Serial/Modem Config writes those
       same params — including the modem init string (raw AT) and destination
       dial numbers — so an admin session can point the BMC at an arbitrary
       number and (via PEF alerting / callback) make it dial out. Admin,
       destructive, --yes-gated.

WIRE   Get Serial/Modem Config (Transport 0x0C / cmd 0x11): req [channel, param,
       set-selector, block-selector]; resp [cc, param-rev, config-data...].
       Set Serial/Modem Config (0x0C / cmd 0x10): req [channel, param,
       config-data...]; resp [cc].

NOTE   Parameter numbers are per IPMI 2.0 §25 (Table 25-*). The name map below is
       best-effort for the classic params; the raw bytes are always faithful, so
       unlabeled params still show their value. Cross-check with the spec / tool
       sources when weaponizing (see docs / the modem research task).
"""
from __future__ import annotations

# Serial/Modem config parameter selectors — authoritative, per IPMI 2.0 §25
# Table 25-4, cross-confirmed against freeipmi (ipmi-serial-modem-configuration-
# parameters-spec.h) and ipmiutil (iserial.c serparams[]). Raw data is faithful
# regardless; these are the correct names.
SERIAL_PARAM: dict[int, str] = {
    0: "set_in_progress", 1: "auth_type_support", 2: "auth_type_enables",
    3: "connection_mode", 4: "session_inactivity_timeout",
    5: "channel_callback_control", 6: "session_termination",
    7: "ipmi_msg_comm_settings", 8: "mux_switch_control", 9: "modem_ring_time",
    10: "modem_init_string", 11: "modem_escape_seq", 12: "modem_hangup_seq",
    13: "modem_dial_command", 14: "page_blackout_interval", 15: "community_string",
    16: "num_alert_destinations", 17: "destination_info", 18: "call_retry_interval",
    19: "destination_comm_settings", 20: "num_dial_strings",
    21: "destination_dial_strings",          # <-- the phone number(s) dialed
    22: "num_alert_dest_ip_addrs", 23: "destination_ip_addrs",
    24: "num_tap_accounts", 25: "tap_account", 26: "tap_passwords",
    27: "tap_pager_id_strings", 28: "tap_service_settings",
    29: "terminal_mode_config", 30: "ppp_protocol_options",
    31: "ppp_primary_rmcp_port", 32: "ppp_secondary_rmcp_port", 33: "ppp_link_auth",
    34: "chap_name", 35: "ppp_accm", 36: "ppp_snoop_accm", 37: "num_ppp_account",
    38: "ppp_account_dial_string_selector", 39: "ppp_account_bmc_ip_addresses",
    40: "ppp_account_user_names", 41: "ppp_account_user_domains",
    42: "ppp_account_user_passwords", 43: "ppp_account_auth_settings",
    44: "ppp_account_connection_hold_times", 45: "ppp_udp_proxy_ip_header_data",
    46: "ppp_udp_proxy_transmit_buffer_size", 47: "ppp_udp_proxy_receive_buffer_size",
    48: "ppp_remote_console_ip_address",
}

# Params whose payload is ASCII text — dial numbers / AT strings / names live here.
_ASCII_PARAMS = {10, 11, 12, 13, 15, 21, 25, 27, 34, 40, 41}


def _ascii(b: bytes) -> str | None:
    s = bytes(x for x in b if 0x20 <= x < 0x7F)
    return s.decode("ascii") if s else None


def get_serial_param(sender, channel: int, param: int,
                     set_sel: int = 0, block_sel: int = 0) -> bytes | None:
    """One Get Serial/Modem Config value; config bytes with the leading
    parameter-revision byte stripped. None on any error/cc!=0."""
    from ..scapy_ipmi.commands import GetSerialConfigReq
    try:
        cc, data = sender.send_raw(
            0x0C, 0x11,
            bytes(GetSerialConfigReq(channel=channel & 0x0F, parameter_selector=param,
                                     set_selector=set_sel, block_selector=block_sel)))
    except Exception:
        return None
    if cc != 0x00 or len(data) < 1:
        return None
    return data[1:]


def serial_config_sweep(sender, channel: int,
                        params=range(0, 49)) -> list[dict]:
    """Read every serial/modem config parameter that answers. Returns
    [{param, name, raw(hex), ascii?}] — the deep serial recon."""
    out: list[dict] = []
    for p in params:
        v = get_serial_param(sender, channel, p)
        if v is None:
            continue
        row = {"param": p, "name": SERIAL_PARAM.get(p, f"param-{p}"),
               "raw": v.hex()}
        if p in _ASCII_PARAMS:
            a = _ascii(v)
            if a:
                row["ascii"] = a
        out.append(row)
    return out


def set_serial_param(sender, channel: int, param: int, data: bytes):
    """Set Serial/Modem Config (0x0C/0x10). Returns (cc, resp). WRITE — the
    caller must gate this (admin/--yes)."""
    from ..scapy_ipmi.commands import SetSerialConfigReq
    return sender.send_raw(
        0x0C, 0x10,
        bytes(SetSerialConfigReq(channel=channel & 0x0F, parameter_selector=param,
                                 data=bytes(data))))


def build_set_string_param(channel: int, param: int, block: int,
                           text: bytes) -> bytes:
    """Request data for setting a block of a string param (init/dial/escape).
    Layout: [channel, param, block-selector, up-to-16 text bytes]. Used by the
    dial-out primitive to write the modem init string or a destination dial
    number."""
    return bytes([channel & 0x0F, param, block & 0xFF]) + bytes(text[:16])
