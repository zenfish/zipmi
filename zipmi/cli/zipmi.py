"""
zipmi.cli.zipmi — argparse front-end for the zipmi library.

WHAT     The `zipmi` shell entry point. Mirrors the most common
         `ipmitool` verbs (`mc info`, `chassis status/power`, `sel info`,
         `raw`, `mc reset`) plus a `scan` extra for sessionless probing.

WHY      A real CLI gives us an apples-to-apples ipmitool replacement for
         live BMC work plus a stable surface for shell scripts and
         experiments.

SUCCESS  `zipmi -H 192.168.0.23 -U root -P calvin mc info` prints a
         block of fields matching ipmitool's `mc info` output for the
         same target.

TARGET   IPMI 1.5 LAN today (Phase 2). RMCP+ ('-I lanplus') comes in
         Phase 3.

BUILD    `pip install -e .` — exposes the `zipmi` console script via
         pyproject.toml [project.scripts].

RUN      zipmi [-H host] [-U user] [-P pass] [-A auth] [-t timeout]
                <verb> ...

         Verbs:
           mc info | mc reset cold|warm
           chassis status | chassis power on|off|cycle|reset|soft
           sel info
           raw <netfn> <cmd> [byte ...]
           scan auth-caps     # sessionless Get Channel Auth Caps
           scan asf-ping
           scan cipher-suites
           scan all

EXIT     0 on success; 1 on IPMI / transport error; 2 on usage error.

RELATED  zipmi/core.py, zipmi/scapy_ipmi/commands.py
"""

from __future__ import annotations

import argparse
import os
import socket
import sys

from ..consts import COMP_CODE, IANA, guess_bmc_generation
from ..core import (
    AUTH_MD5,
    AUTH_NONE,
    AUTH_STRAIGHT,
    IPMIError,
    Session,
    Transport,
)
from ..scapy_ipmi.asf import build_ping, parse_pong
from ..scapy_ipmi.commands import (
    BOOT_DEVICE,
    CHASSIS_CTRL,
    ChassisControlReq,
    GetChanAuthCapsReq,
    GetChannelInfoReq,
    GetSDRReq,
    GetSELEntryReq,
    GetSensorReadingReq,
    GetSystemBootOptionsReq,
    GetUserAccessReq,
    GetUserNameReq,
    SetSystemBootOptionsReq,
    decode_sol_bitrate,
    encode_boot_flags,
    encode_sol_bitrate,
)
from ..scapy_ipmi.rmcp import RMCP


AUTH_BY_NAME = {
    "none":     AUTH_NONE,
    "password": AUTH_STRAIGHT,
    "md5":      AUTH_MD5,
}


# Commands the IPMI 2.0 spec lists as sendable outside a session
# (Table 22-25 + §13.6). The vendor/channel config still gates whether
# the BMC will actually answer — see VIRTUAL-BMC.md / docs for nuance.
PRE_SESSION_CMDS: dict[tuple[int, int], str] = {
    (0x06, 0x37): "Get System GUID",
    (0x06, 0x38): "Get Channel Authentication Capabilities",
    (0x06, 0x39): "Get Session Challenge",
    (0x06, 0x3A): "Activate Session",
    (0x06, 0x54): "Get Channel Cipher Suites",
}


# -- argument plumbing ----------------------------------------------------


def add_globals(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Position-independent global flags.

    suppress=True => every default is argparse.SUPPRESS, so re-parsing the
    globals-stripped remainder never clobbers values the pre-pass set.
    """
    def d(real):
        return argparse.SUPPRESS if suppress else real

    parser.add_argument("-H", "--host",
                        default=d(os.environ.get("ZIPMI_TARGET")),
                        help="BMC IP/hostname (env: ZIPMI_TARGET)")
    parser.add_argument("-p", "--port", type=int, default=d(623),
                        help="UDP port (default 623)")
    parser.add_argument("-U", "--user",
                        default=d(os.environ.get("ZIPMI_USER")),
                        help="username (env: ZIPMI_USER). If neither -U nor "
                             "-P is given, requests are sent sessionless.")
    parser.add_argument("-P", "--password",
                        default=d(os.environ.get("ZIPMI_PASS")),
                        help="password (env: ZIPMI_PASS)")
    parser.add_argument("-A", "--auth", choices=AUTH_BY_NAME.keys(),
                        default=d("md5"),
                        help="auth type for IPMI 1.5 session (default md5)")
    parser.add_argument("-I", "--interface", choices=["lan", "lanplus"],
                        default=d("lan"),
                        help="lan = IPMI 1.5; lanplus = IPMI 2.0 RMCP+ "
                             "(default lan)")
    parser.add_argument("-C", "--cipher", type=int, default=d(3),
                        help="lanplus cipher suite (default 3 = "
                             "HMAC-SHA1+AES-CBC-128)")
    parser.add_argument("-t", "--timeout", type=float, default=d(3.0),
                        help="UDP timeout in seconds (default 3.0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=d(False),
                        help="log high-level events with timestamps (no hex)")
    parser.add_argument("-d", "--debug", action="store_true",
                        default=d(False),
                        help="-v + hex-dump every packet (incl. session "
                             "setup)")
    parser.add_argument("-n", "--no-color", action="store_true",
                        default=d(False),
                        help="disable ANSI colour in wire-trace hex output")
    parser.add_argument("--palette", default=d(None),
                        choices=["auto", "a", "pastel", "p",
                                 "set", "s", "dark", "d"],
                        metavar="{auto/a,pastel/p,set/s,dark/d}",
                        help="colour palette (default: auto — detects "
                             "terminal background)")


def parse_cli(argv: list[str] | None = None) -> argparse.Namespace:
    """Two-pass parse: strip globals from anywhere, then parse the
    verb/action remainder into the same namespace."""
    pre = argparse.ArgumentParser(add_help=False)
    add_globals(pre, suppress=False)
    ns, rest = pre.parse_known_args(argv)
    parser = build_parser()
    parser.parse_args(rest, namespace=ns)
    return ns


def _require_host(args: argparse.Namespace) -> str:
    if not args.host:
        print("error: --host required (or set ZIPMI_TARGET)", file=sys.stderr)
        sys.exit(2)
    return args.host


def _apply_trace(transport, args: argparse.Namespace) -> None:
    """Push -v/-d/-n/-p flags onto a Transport instance.

    Used by both `_open_session` and the sessionless `scan` verbs so
    that `zipmi scan asf-ping -v` traces the wire just like
    `zipmi mc info -v` does.
    """
    if getattr(args, "debug", False):
        transport.wire_trace = 2
    elif getattr(args, "verbose", False):
        transport.wire_trace = 1
    # Wire-trace colour: on by default when stdout is a TTY and the
    # caller hasn't disabled it via -n / --no-color or the NO_COLOR
    # environment variable (https://no-color.org).
    from ..scapy_ipmi.colorize import (
        color_enabled, normalize_palette_name, resolve_palette, set_palette,
    )
    transport.wire_color = (
        color_enabled() and not getattr(args, "no_color", False)
    )
    palette = getattr(args, "palette", None)
    if palette:
        try:
            set_palette(resolve_palette(normalize_palette_name(palette)))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)


def _open_session(args: argparse.Namespace) -> Session:
    """Build a Session; the caller activates via `with` block.

    No creds (both -U and -P unset) → sessionless mode: Session skips the
    handshake and every send goes out auth_type=0, session_id=0. The BMC
    decides what it'll answer at that privilege.
    """
    if (args.user is None) != (args.password is None):
        print("error: -U and -P must both be given (or neither). "
              "Pass nothing for sessionless mode.", file=sys.stderr)
        sys.exit(2)
    lanplus = (args.interface == "lanplus")
    s = Session(
        host=_require_host(args),
        username=args.user,
        password=args.password,
        auth_type=AUTH_BY_NAME[args.auth],
        timeout=args.timeout,
        lanplus=lanplus,
        cipher_suite=args.cipher,
    )
    s.transport.port = args.port
    _apply_trace(s.transport, args)
    return s


# -- verb handlers --------------------------------------------------------


def cmd_mc_info(args: argparse.Namespace) -> int:
    with _open_session(args) as s:
        d = s.get_device_id()
    iana = d.manufacturer_id_int()
    print(f"Device ID                 : {d.device_id}")
    print(f"Device Revision           : {d.device_revision & 0x0F}")
    print(f"Firmware Revision         : {d.fw_revision()}")
    print(f"IPMI Version              : 0x{d.ipmi_version:02x}")
    print(f"Manufacturer ID           : {iana}")
    print(f"Manufacturer Name         : {IANA.get(iana, 'unknown')}")
    print(f"Manufacturer Generation   : {guess_bmc_generation(iana, d.product_id)}")
    print(f"Product ID                : {d.product_id} (0x{d.product_id:04x})")
    print(f"Device Available          : {'yes' if not (d.fw_revision_1 & 0x80) else 'no (init)'}")
    print(f"Provides Device SDRs      : {'yes' if (d.device_revision & 0x80) else 'no'}")
    print(f"Additional Device Support : 0x{d.additional_dev_support:02x}")
    return 0


def cmd_mc_reset(args: argparse.Namespace) -> int:
    cmd = 0x02 if args.kind == "cold" else 0x03
    with _open_session(args) as s:
        # Reset commands sometimes reply, sometimes the BMC just goes away
        # mid-response. Tolerate timeout.
        try:
            s.send_cmd(0x06, cmd)
        except (OSError, socket.timeout):
            pass
    print(f"Sent {args.kind} reset to {args.host}")
    return 0


def cmd_chassis_status(args: argparse.Namespace) -> int:
    with _open_session(args) as s:
        c = s.get_chassis_status()
    print(f"System Power         : {'on' if c.power_on() else 'off'}")
    print(f"Power Restore Policy : {(c.current_power_state >> 5) & 0x3}")
    print(f"Power Control Fault  : {(c.current_power_state >> 4) & 0x1}")
    print(f"Power Fault          : {(c.current_power_state >> 3) & 0x1}")
    print(f"Power Interlock      : {(c.current_power_state >> 2) & 0x1}")
    print(f"Main Power Fault     : {(c.current_power_state >> 1) & 0x1}")
    print(f"Last Power Event     : 0x{c.last_power_event:02x}")
    print(f"Misc Chassis State   : 0x{c.misc_chassis_state:02x}")
    return 0


def cmd_chassis_power(args: argparse.Namespace) -> int:
    code_by_name = {v: k for k, v in CHASSIS_CTRL.items()}
    if args.action not in code_by_name:
        print(f"error: unknown power action '{args.action}'", file=sys.stderr)
        return 2
    if args.action != "status" and not args.yes:
        print(f"warning: '{args.action}' affects host power. Pass --yes to proceed.",
              file=sys.stderr)
        return 2
    with _open_session(args) as s:
        s.send_cmd(0x00, 0x02, ChassisControlReq(action=code_by_name[args.action]))
    print(f"chassis power {args.action} sent to {args.host}")
    return 0


RESTART_CAUSE: dict[int, str] = {
    0x00: "unknown",
    0x01: "chassis control command",
    0x02: "reset button",
    0x03: "power button",
    0x04: "watchdog expiration",
    0x05: "OEM",
    0x06: "auto power-up: always restore",
    0x07: "auto power-up: restore previous",
    0x08: "PEF reset",
    0x09: "PEF power cycle",
    0x0A: "soft reset",
    0x0B: "RTC wake-up",
}

POWER_POLICY: dict[str, int] = {
    "always-off": 0x00,
    "previous":   0x01,
    "always-on":  0x02,
}


def cmd_chassis_restart_cause(args: argparse.Namespace) -> int:
    """Get System Restart Cause (0x00/0x07).

    Response: byte 0 bits 3:0 = cause, byte 1 = channel of remote command.
    """
    with _open_session(args) as s:
        cc, data = s.send_raw(0x00, 0x07, b"")
        if cc != 0x00 or len(data) < 2:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    cause = data[0] & 0x0F
    chan = data[1] & 0x0F
    name = RESTART_CAUSE.get(cause, f"0x{cause:02x}")
    print(f"System restart cause : {name}")
    print(f"Channel              : 0x{chan:x}")
    return 0


def cmd_chassis_policy(args: argparse.Namespace) -> int:
    """Set Power Restore Policy (0x00/0x06).

    Action 'list' uses the no-change variant (0x03) to ask which policies
    the BMC supports without changing state. Otherwise the named policy
    is applied.
    """
    if args.policy == "list":
        with _open_session(args) as s:
            cc, data = s.send_raw(0x00, 0x06, b"\x03")
        if cc != 0x00 or not data:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
        bits = data[0]
        supported = [name for name, code in POWER_POLICY.items()
                     if bits & (1 << code)]
        print(f"Supported policies: {', '.join(supported) or '(none reported)'}")
        return 0
    code = POWER_POLICY[args.policy]
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x00, 0x06, bytes([code]))
        if cc != 0x00:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    print(f"Power restore policy set: {args.policy}")
    return 0


def cmd_sel_info(args: argparse.Namespace) -> int:
    with _open_session(args) as s:
        si = s.send_cmd(0x0A, 0x40)
    print(f"SEL Version          : 0x{si.version:02x}")
    print(f"Entries              : {si.entries}")
    print(f"Free Space (bytes)   : {si.free_space}")
    print(f"Last Add Timestamp   : {si.last_add_ts}")
    print(f"Last Erase Timestamp : {si.last_del_ts}")
    print(f"Operation Support    : 0x{si.op_support:02x}")
    return 0


def _decode_sel_record(rec: bytes) -> str:
    """Decode a 16-byte standard SEL record into a one-line summary."""
    if len(rec) < 16:
        return f"  short record ({len(rec)} bytes)"
    record_id = int.from_bytes(rec[0:2], "little")
    rec_type = rec[2]
    ts = int.from_bytes(rec[3:7], "little")
    gen_id = int.from_bytes(rec[7:9], "little")
    sensor_type = rec[10]
    sensor_num = rec[11]
    ev_byte = rec[12]
    ev_data = rec[13:16]
    direction = "asserted" if not (ev_byte & 0x80) else "deasserted"
    return (
        f"{record_id:5d} | type=0x{rec_type:02x} ts={ts} "
        f"gen=0x{gen_id:04x} sensor=0x{sensor_type:02x}/{sensor_num} "
        f"ev=0x{ev_byte:02x} ({direction}) data={ev_data.hex()}"
    )


def cmd_sel_list(args: argparse.Namespace) -> int:
    """Walk the SEL via Reserve + Get Entry sequence."""
    with _open_session(args) as s:
        info = s.send_cmd(0x0A, 0x40)
        if info.entries == 0:
            print("(SEL is empty)")
            return 0
        # Reserve SEL.
        rsv = s.send_cmd(0x0A, 0x42)
        rid = rsv.reservation_id
        print(f"SEL: {info.entries} entries (reservation 0x{rid:04x})")
        record_id = 0x0000
        seen = 0
        max_iter = info.entries + 4   # safety stop for circular nextids
        while seen < max_iter:
            try:
                resp = s.send_cmd(
                    0x0A, 0x43,
                    GetSELEntryReq(reservation_id=rid, record_id=record_id,
                                   offset=0, count=0xFF),
                )
            except Exception as e:
                print(f"  abort at record 0x{record_id:04x}: {e}", file=sys.stderr)
                return 1
            print(_decode_sel_record(bytes(resp.record)))
            seen += 1
            next_id = resp.next_record_id
            if next_id == 0xFFFF:
                break
            record_id = next_id
    return 0


def _build_sdr_sensor_map(s) -> dict:
    """Walk the SDR repository, return {sensor_num: SensorInfo} for Type 1/2.

    Best-effort: any per-record failure is logged to stderr and skipped, the
    walk continues. Returns {} if the SDR repo is empty or initial reserve
    fails — `elist` then degrades to '#0xNN' sensor labels.
    """
    from ..sel_decode import decode_sdr_record
    out: dict = {}
    try:
        info = s.send_cmd(0x0A, 0x20)
        if info.record_count == 0:
            return out
        rsv = s.send_cmd(0x0A, 0x22)
        rid = rsv.reservation_id
    except Exception as e:
        print(f"  SDR walk skipped: {e}", file=sys.stderr)
        return out
    record_id = 0x0000
    seen = 0
    while seen < info.record_count + 4:
        try:
            hdr = s.send_cmd(
                0x0A, 0x23,
                GetSDRReq(reservation_id=rid, record_id=record_id,
                          offset=0, count=5),
            )
        except Exception as e:
            print(f"  SDR abort at 0x{record_id:04x}: {e}", file=sys.stderr)
            return out
        d = bytes(hdr.record_data)
        if len(d) < 5:
            break
        rec_type = d[3]
        length = d[4]
        total_len = 5 + length
        next_id = hdr.next_record_id
        if rec_type in (0x01, 0x02):
            try:
                next_id, full = _read_sdr_record(s, rid, record_id, total_len)
                info_rec = decode_sdr_record(full)
                if info_rec is not None and info_rec.name:
                    out[info_rec.sensor_num] = info_rec
            except Exception as e:
                print(f"  SDR record 0x{record_id:04x}: {e}", file=sys.stderr)
        seen += 1
        if next_id == 0xFFFF:
            break
        record_id = next_id
    return out


def cmd_sel_elist(args: argparse.Namespace) -> int:
    """Extended SEL list. Mirrors ipmitool's `sel elist`:

      - Resolves sensor names via SDR walk (degrades to '#0xNN' on failure).
      - Decodes timestamps to MM/DD/YYYY HH:MM:SS UTC.
      - Decodes event-type/offset to human text (generic + sensor-specific).
      - Prints Asserted/Deasserted from event direction bit.
    """
    from ..sel_decode import format_sel_record_extended
    with _open_session(args) as s:
        sdr_map = _build_sdr_sensor_map(s)
        info = s.send_cmd(0x0A, 0x40)
        if info.entries == 0:
            print("(SEL is empty)")
            return 0
        rsv = s.send_cmd(0x0A, 0x42)
        rid = rsv.reservation_id
        print(f"SEL: {info.entries} entries "
              f"({len(sdr_map)} sensors named via SDR)")
        record_id = 0x0000
        seen = 0
        max_iter = info.entries + 4
        while seen < max_iter:
            try:
                resp = s.send_cmd(
                    0x0A, 0x43,
                    GetSELEntryReq(reservation_id=rid, record_id=record_id,
                                   offset=0, count=0xFF),
                )
            except Exception as e:
                print(f"  abort at record 0x{record_id:04x}: {e}",
                      file=sys.stderr)
                return 1
            print(format_sel_record_extended(bytes(resp.record), sdr_map))
            seen += 1
            next_id = resp.next_record_id
            if next_id == 0xFFFF:
                break
            record_id = next_id
    return 0


def cmd_sel_clear(args: argparse.Namespace) -> int:
    """Clear the SEL via Reserve + Clear SEL (0x0A/0x47).

    Spec (§31.9): payload = reservation_id LE + 'C' 'L' 'R' + opcode.
    opcode 0xAA = initiate erase; 0x00 = get erase status.
    Response byte 0: bit 0..3 = erase status (0=in-progress, 1=complete).
    """
    with _open_session(args) as s:
        rsv = s.send_cmd(0x0A, 0x42)
        rid = rsv.reservation_id
        clr = bytes([rid & 0xFF, (rid >> 8) & 0xFF]) + b"CLR" + b"\xAA"
        cc, data = s.send_raw(0x0A, 0x47, clr)
        if cc != 0x00:
            print(f"  clear initiate failed: cc=0x{cc:02x}", file=sys.stderr)
            return 1
        # Poll erase status. Most BMCs complete in <1s but spec allows longer.
        import time
        for _ in range(20):
            poll = bytes([rid & 0xFF, (rid >> 8) & 0xFF]) + b"CLR" + b"\x00"
            cc, data = s.send_raw(0x0A, 0x47, poll)
            if cc != 0x00:
                print(f"  status poll failed: cc=0x{cc:02x}", file=sys.stderr)
                return 1
            status = data[0] & 0x0F if data else 0
            if status == 1:
                print("SEL cleared")
                return 0
            time.sleep(0.25)
        print("  clear timed out (still in progress)", file=sys.stderr)
        return 1


def cmd_sel_time_get(args: argparse.Namespace) -> int:
    """Get SEL Time (0x0A/0x48). 4-byte LE seconds since 1970-01-01 UTC."""
    from datetime import datetime, timezone
    with _open_session(args) as s:
        cc, data = s.send_raw(0x0A, 0x48, b"")
        if cc != 0x00 or len(data) < 4:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    ts = int.from_bytes(data[:4], "little")
    if ts < 0x20000000:
        print(f"SEL Time : Pre-Init (raw=0x{ts:08x})")
    else:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
        print(f"SEL Time : {dt.strftime('%m/%d/%Y %H:%M:%S %Z')} (raw=0x{ts:08x})")
    return 0


def cmd_sel_time_set(args: argparse.Namespace) -> int:
    """Set SEL Time (0x0A/0x49). Argument is either an epoch int or 'now'."""
    from datetime import datetime, timezone
    raw = args.timestamp
    if raw == "now":
        ts = int(datetime.now(tz=timezone.utc).timestamp())
    else:
        try:
            ts = int(raw, 0)
        except ValueError:
            print(f"  bad timestamp: {raw!r} (use 'now' or seconds-since-epoch)",
                  file=sys.stderr)
            return 1
    payload = ts.to_bytes(4, "little")
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x0A, 0x49, payload)
        if cc != 0x00:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    print(f"SEL Time set: {dt.strftime('%m/%d/%Y %H:%M:%S %Z')}")
    return 0


def cmd_sdr_list(args: argparse.Namespace) -> int:
    """Walk the SDR repository.

    Prints record_id and record_type for each record. Full record decode
    is deferred to a future revision (variable layouts per Type 1/2/11/12).
    """
    with _open_session(args) as s:
        info = s.send_cmd(0x0A, 0x20)
        print(f"SDR Version    : 0x{info.sdr_version:02x}")
        print(f"Record Count   : {info.record_count}")
        print(f"Free Space     : {info.free_space} bytes")
        if info.record_count == 0:
            return 0
        rsv = s.send_cmd(0x0A, 0x22)
        rid = rsv.reservation_id
        record_id = 0x0000
        seen = 0
        while seen < info.record_count + 4:
            # First read 5-byte SDR header to learn record length.
            try:
                resp = s.send_cmd(
                    0x0A, 0x23,
                    GetSDRReq(reservation_id=rid, record_id=record_id,
                              offset=0, count=5),
                )
            except Exception as e:
                print(f"  abort at SDR 0x{record_id:04x}: {e}", file=sys.stderr)
                return 1
            data = bytes(resp.record_data)
            if len(data) >= 5:
                rec_id = int.from_bytes(data[0:2], "little")
                version = data[2]
                rec_type = data[3]
                length = data[4]
                print(f"  SDR 0x{rec_id:04x}: type=0x{rec_type:02x} "
                      f"version=0x{version:02x} len={length}")
            seen += 1
            next_id = resp.next_record_id
            if next_id == 0xFFFF:
                break
            record_id = next_id
    return 0


def cmd_user_list(args: argparse.Namespace) -> int:
    """Walk users 1..max via Get User Access + Get User Name."""
    with _open_session(args) as s:
        # Probe user 1 to discover max_user_count.
        ua1 = s.send_cmd(0x06, 0x44, GetUserAccessReq(channel=0xE, user_id=1))
        max_users = ua1.max_user_count & 0x3F
        print(f"max_user_count={max_users}  enabled={ua1.enabled_user_count & 0x3F}")
        print(f"{'ID':>3}  {'Name':16}  {'Access':10}")
        for uid in range(1, max_users + 1):
            try:
                ua = s.send_cmd(0x06, 0x44,
                                GetUserAccessReq(channel=0xE, user_id=uid))
                un = s.send_cmd(0x06, 0x46, GetUserNameReq(user_id=uid))
            except Exception as e:
                print(f"  user {uid}: {e}", file=sys.stderr)
                continue
            name = bytes(un.user_name).rstrip(b"\x00").decode("utf-8", errors="replace")
            access = ua.user_access
            print(f"{uid:3}  {name:16}  0x{access:02x}")
    return 0


PRIV_LEVELS: dict[str, int] = {
    "callback":  0x01,
    "user":      0x02,
    "operator":  0x03,
    "admin":     0x04,
    "oem":       0x05,
    "no-access": 0x0F,
}


def _guard_write_user(args: argparse.Namespace, what: str) -> bool:
    """User-table writes can lock you out of the BMC. Require --yes."""
    if not args.yes:
        print(f"warning: '{what}' modifies the BMC user table. Pass --yes to proceed.",
              file=sys.stderr)
        return False
    return True


def cmd_user_set_name(args: argparse.Namespace) -> int:
    """Set User Name (0x06/0x45). Name padded to 16 bytes with NULs."""
    if not _guard_write_user(args, "user set name"):
        return 2
    uid = args.user_id
    if not 1 <= uid <= 63:
        print(f"  user_id {uid} out of range 1..63", file=sys.stderr)
        return 2
    name = args.name.encode("utf-8")
    if len(name) > 16:
        print(f"  name too long ({len(name)} > 16 bytes)", file=sys.stderr)
        return 2
    payload = bytes([uid & 0x3F]) + name.ljust(16, b"\x00")
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x06, 0x45, payload)
        if cc != 0x00:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    print(f"user {uid}: name set to {args.name!r}")
    return 0


def _user_password_op(args: argparse.Namespace, op: int, password: bytes = b"") -> int:
    """Set User Password (0x06/0x47).

    op: 0=disable, 1=enable, 2=set, 3=test.
    password buffer pads to 16 (or 20 with bit 7 in byte 0).
    """
    uid = args.user_id
    if not 1 <= uid <= 63:
        print(f"  user_id {uid} out of range 1..63", file=sys.stderr)
        return 2
    size = getattr(args, "size", 16)
    if size not in (16, 20):
        print(f"  password size must be 16 or 20", file=sys.stderr)
        return 2
    if len(password) > size:
        print(f"  password too long ({len(password)} > {size})", file=sys.stderr)
        return 2
    size_bit = 0x80 if size == 20 else 0x00
    payload = bytes([(uid & 0x3F) | size_bit, op & 0x03])
    if op in (0x02, 0x03):
        payload += password.ljust(size, b"\x00")
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x06, 0x47, payload)
        if cc != 0x00:
            # CC 0x80 = password test failed.
            if op == 0x03 and cc == 0x80:
                print("password test: MISMATCH")
                return 1
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    return 0


def cmd_user_enable(args: argparse.Namespace) -> int:
    if not _guard_write_user(args, "user enable"):
        return 2
    rc = _user_password_op(args, op=0x01)
    if rc == 0:
        print(f"user {args.user_id}: enabled")
    return rc


def cmd_user_disable(args: argparse.Namespace) -> int:
    if not _guard_write_user(args, "user disable"):
        return 2
    rc = _user_password_op(args, op=0x00)
    if rc == 0:
        print(f"user {args.user_id}: disabled")
    return rc


def cmd_user_set_password(args: argparse.Namespace) -> int:
    if not _guard_write_user(args, "user set password"):
        return 2
    pw = args.new_password.encode("utf-8")
    rc = _user_password_op(args, op=0x02, password=pw)
    if rc == 0:
        print(f"user {args.user_id}: password set ({args.size}-byte slot)")
    return rc


def cmd_user_test_password(args: argparse.Namespace) -> int:
    """Test User Password (0x06/0x47 op 0x03). Read-only — no --yes guard."""
    pw = args.test_password.encode("utf-8")
    rc = _user_password_op(args, op=0x03, password=pw)
    if rc == 0:
        print("password test: OK")
    return rc


def cmd_user_priv(args: argparse.Namespace) -> int:
    """Set User Access (0x06/0x43). Updates privilege level for the given
    user on the given channel. Leaves callin/link-auth/ipmi-msg bits alone
    (byte-0 bit 7 = 0 = don't change those bits)."""
    if not _guard_write_user(args, "user priv"):
        return 2
    uid = args.user_id
    level = PRIV_LEVELS[args.level]
    chan = args.channel
    # byte 0: bit 7 = 0 (don't touch the byte-1 flags); bits 3:0 = channel
    # byte 1: bits 3:0 = user_id (callin/link/ipmi bits ignored without bit 7)
    # byte 2: bits 3:0 = privilege
    # byte 3: bits 3:0 = session limit (0 = no limit)
    payload = bytes([chan & 0x0F, uid & 0x3F, level & 0x0F, 0x00])
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x06, 0x43, payload)
        if cc != 0x00:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    print(f"user {uid} channel 0x{chan:x}: privilege set to {args.level}")
    return 0


CHANNEL_MEDIUM: dict[int, str] = {
    0x00: "reserved",
    0x01: "IPMB (I2C)",
    0x02: "ICMB v1.0",
    0x03: "ICMB v0.9",
    0x04: "802.3 LAN",
    0x05: "asynch serial/modem",
    0x06: "other LAN",
    0x07: "PCI SMBus",
    0x08: "SMBus v1.0/1.1",
    0x09: "SMBus v2.0",
    0x0A: "USB 1.x",
    0x0B: "USB 2.x",
    0x0C: "system interface (KCS/SMIC/BT)",
}

CHANNEL_PROTOCOL: dict[int, str] = {
    0x00: "reserved",
    0x01: "IPMB-1.0",
    0x02: "ICMB v1.0",
    0x04: "IPMI-over-LAN (RMCP+)",
    0x05: "IPMI-over-Serial",
    0x06: "TMODE",
    0x07: "OEM 1",
    0x08: "OEM 2",
    0x09: "OEM 3",
    0x0A: "OEM 4",
}

SESSION_SUPPORT: dict[int, str] = {
    0b00: "session-less",
    0b01: "single-session",
    0b10: "multi-session",
    0b11: "session-based (auto)",
}


def cmd_channel_info(args: argparse.Namespace) -> int:
    """Get Channel Info Command (0x06/0x42)."""
    chan = args.channel
    with _open_session(args) as s:
        cc, data = s.send_raw(0x06, 0x42, bytes([chan & 0x0F]))
        if cc != 0x00 or len(data) < 9:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    actual = data[0] & 0x0F
    medium = data[1] & 0x7F
    proto = data[2] & 0x1F
    sess_support = (data[3] >> 6) & 0x03
    active = data[3] & 0x3F
    vendor_id = data[4] | (data[5] << 8) | (data[6] << 16)
    print(f"Channel 0x{actual:x} info:")
    print(f"  Medium type      : {CHANNEL_MEDIUM.get(medium, f'0x{medium:02x}')}")
    print(f"  Protocol type    : {CHANNEL_PROTOCOL.get(proto, f'0x{proto:02x}')}")
    print(f"  Session support  : {SESSION_SUPPORT[sess_support]}")
    print(f"  Active sessions  : {active}")
    print(f"  Vendor IANA      : 0x{vendor_id:06x}")
    print(f"  Aux info         : 0x{data[7]:02x}{data[8]:02x}")
    return 0


def cmd_channel_getaccess(args: argparse.Namespace) -> int:
    """Get User Access (0x06/0x44) on a specific channel + user."""
    payload = bytes([args.channel & 0x0F, args.user_id & 0x3F])
    with _open_session(args) as s:
        cc, data = s.send_raw(0x06, 0x44, payload)
        if cc != 0x00 or len(data) < 4:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    # IPMI 2.0 §22.27 Table 22-9:
    #   byte 1 [5:0]  = max user IDs
    #   byte 2 [7:6]  = enabled status (0=unspec, 1=enabled, 2=disabled)
    #          [5:0]  = enabled user count
    #   byte 3 [5:0]  = fixed-name user count
    #   byte 4 [6]    = callin/callback access available
    #          [5]    = link auth enabled
    #          [4]    = IPMI messaging enabled
    #          [3:0]  = privilege limit
    max_uid = data[0] & 0x3F
    enabled_status = (data[1] >> 6) & 0x03
    enabled_count = data[1] & 0x3F
    fixed_users = data[2] & 0x3F
    # Byte 4 bit semantics per ipmitool / observed BMC behavior:
    #   [6] 1 = restricted to callback only (no call-in); 0 = both allowed
    #   [5] 1 = link auth enabled
    #   [4] 1 = IPMI messaging enabled
    access = data[3]
    priv = access & 0x0F
    callin = not bool(access & 0x40)
    link_auth = bool(access & 0x20)
    ipmi_msg = bool(access & 0x10)
    priv_name = next((n for n, v in PRIV_LEVELS.items() if v == priv),
                     f"0x{priv:x}")
    enabled = {0: "unspecified", 1: "enabled", 2: "disabled"}.get(enabled_status, "?")
    print(f"Channel 0x{args.channel:x}, user {args.user_id}:")
    print(f"  Max user IDs       : {max_uid}")
    print(f"  Enabled user count : {enabled_count}")
    print(f"  Fixed-name users   : {fixed_users}")
    print(f"  Enable status      : {enabled}")
    print(f"  IPMI messaging     : {'on' if ipmi_msg else 'off'}")
    print(f"  Link authentication: {'on' if link_auth else 'off'}")
    print(f"  Callin/callback    : {'on' if callin else 'off'}")
    print(f"  Privilege level    : {priv_name}")
    return 0


def cmd_session_info(args: argparse.Namespace) -> int:
    """Get Session Info (0x06/0x3D).

    selector 0x00 = current active session (most useful — returns info
    about the session we just opened to talk to the BMC).
    """
    sel = args.selector
    if sel == "active":
        payload = b"\x00"
    elif sel.startswith("0x") or sel.startswith("0X"):
        idx = int(sel, 16)
        payload = bytes([idx])
    else:
        idx = int(sel)
        payload = bytes([idx & 0xFF])
    with _open_session(args) as s:
        cc, data = s.send_raw(0x06, 0x3D, payload)
        if cc != 0x00 or len(data) < 6:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    handle = data[0]
    possible = data[1] & 0x3F
    active = data[2] & 0x3F
    uid = data[3] & 0x3F
    op_priv = data[4] & 0x0F
    chan = data[5] & 0x0F
    priv_name = next((n for n, v in PRIV_LEVELS.items() if v == op_priv),
                     f"0x{op_priv:x}")
    print(f"Session handle        : 0x{handle:02x}")
    print(f"Slot total / active   : {possible} / {active}")
    print(f"User ID               : {uid}")
    print(f"Operating privilege   : {priv_name}")
    print(f"Channel               : 0x{chan:x}")
    if len(data) >= 18:
        ip = ".".join(str(b) for b in data[6:10])
        mac = ":".join(f"{b:02x}" for b in data[10:16])
        port = data[16] | (data[17] << 8)
        print(f"Remote IP             : {ip}")
        print(f"Remote MAC            : {mac}")
        print(f"Remote port           : {port}")
    return 0


WDT_USE: dict[int, str] = {
    0x00: "reserved",
    0x01: "BIOS FRB2",
    0x02: "BIOS/POST",
    0x03: "OS Load",
    0x04: "SMS/OS",
    0x05: "OEM",
}

WDT_ACTION: dict[int, str] = {
    0x00: "no action",
    0x01: "hard reset",
    0x02: "power down",
    0x03: "power cycle",
}

WDT_PRE_INT: dict[int, str] = {
    0x00: "none",
    0x01: "SMI",
    0x02: "NMI / diagnostic",
    0x03: "messaging interrupt",
}


def cmd_mc_watchdog_get(args: argparse.Namespace) -> int:
    """Get Watchdog Timer (0x06/0x25)."""
    with _open_session(args) as s:
        cc, data = s.send_raw(0x06, 0x25, b"")
        if cc != 0x00 or len(data) < 8:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    use_byte = data[0]
    use = use_byte & 0x07
    running = bool(use_byte & 0x40)
    dont_log = bool(use_byte & 0x80)
    actions_byte = data[1]
    action = actions_byte & 0x07
    pre_int = (actions_byte >> 4) & 0x07
    pre_to = data[2]
    expir_flags = data[3]
    initial = int.from_bytes(data[4:6], "little") / 10.0
    present = int.from_bytes(data[6:8], "little") / 10.0
    print(f"Watchdog Timer       : {'running' if running else 'stopped'}")
    print(f"Timer use            : {WDT_USE.get(use, f'0x{use:x}')}")
    print(f"Don't log            : {'on' if dont_log else 'off'}")
    print(f"Timer action         : {WDT_ACTION.get(action, f'0x{action:x}')}")
    print(f"Pre-timeout interrupt: {WDT_PRE_INT.get(pre_int, f'0x{pre_int:x}')}")
    print(f"Pre-timeout interval : {pre_to} s")
    print(f"Initial countdown    : {initial:.1f} s")
    print(f"Present countdown    : {present:.1f} s")
    print(f"Expiration flags     : 0x{expir_flags:02x}")
    return 0


def cmd_mc_watchdog_reset(args: argparse.Namespace) -> int:
    """Reset Watchdog Timer (0x06/0x22). Pats the dog."""
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x06, 0x22, b"")
        if cc != 0x00:
            print(f"  cc=0x{cc:02x}", file=sys.stderr)
            return 1
    print("Watchdog timer reset (kicked)")
    return 0


def cmd_mc_watchdog_off(args: argparse.Namespace) -> int:
    """Disable watchdog by writing Set Watchdog Timer (0x06/0x24) with
    the stop bit cleared. Reads current config first to preserve everything
    else, then turns the timer off.
    """
    if not args.yes:
        print("warning: 'mc watchdog off' modifies BMC watchdog state. Pass --yes.",
              file=sys.stderr)
        return 2
    with _open_session(args) as s:
        cc, data = s.send_raw(0x06, 0x25, b"")
        if cc != 0x00 or len(data) < 8:
            print(f"  get cc=0x{cc:02x}", file=sys.stderr)
            return 1
        # Clear running bit (0x40) on the timer-use byte so the BMC stops it.
        use_byte = data[0] & ~0x40
        payload = bytes([use_byte, data[1], data[2], data[3]]) + data[4:6]
        cc, _ = s.send_raw(0x06, 0x24, payload)
        if cc != 0x00:
            print(f"  set cc=0x{cc:02x}", file=sys.stderr)
            return 1
    print("Watchdog timer disabled")
    return 0


def _read_fru_blob(s, device_id: int, total: int, chunk: int = 16) -> bytes:
    """Read Read FRU Data (0x0A/0x11) in chunks until `total` bytes accumulated.

    Some BMCs reject chunk >= 32. 16 is a safe default that always works.
    Returns whatever the BMC handed back (may be shorter than requested).
    """
    out = bytearray()
    while len(out) < total:
        want = min(chunk, total - len(out))
        offset = len(out)
        req = bytes([device_id & 0xFF,
                     offset & 0xFF, (offset >> 8) & 0xFF,
                     want & 0xFF])
        cc, data = s.send_raw(0x0A, 0x11, req)
        if cc != 0x00 or len(data) < 1:
            break
        got = data[0]
        out.extend(data[1: 1 + got])
        if got == 0:
            break
    return bytes(out)


def cmd_fru_print(args: argparse.Namespace) -> int:
    """Print FRU Common Header, Board Info, and Product Info areas.

    Default device ID is 0 (the BMC's own FRU). Chassis Info, Internal
    Use, and MultiRecord areas are summarized by offset only.
    """
    from ..fru import (
        parse_common_header, parse_board_info, parse_product_info,
    )
    dev_id = args.device_id
    with _open_session(args) as s:
        cc, data = s.send_raw(0x0A, 0x10, bytes([dev_id]))
        if cc != 0x00 or len(data) < 3:
            print(f"  FRU inventory info cc=0x{cc:02x}", file=sys.stderr)
            return 1
        size = data[0] | (data[1] << 8)
        access_word = bool(data[2] & 0x01)
        print(f"FRU Device {dev_id}: {size} bytes "
              f"({'word' if access_word else 'byte'} access)")
        blob = _read_fru_blob(s, dev_id, size)
    if len(blob) < 8:
        print(f"  short FRU blob ({len(blob)} bytes)", file=sys.stderr)
        return 1
    hdr = parse_common_header(blob)
    if hdr is None:
        print("  invalid Common Header", file=sys.stderr)
        return 1
    print(f"Common Header        : v{hdr.format_version}"
          f"  checksum {'OK' if hdr.checksum_ok else 'BAD'}")
    print(f"  internal_use offset: {hdr.internal_off}")
    print(f"  chassis_info offset: {hdr.chassis_off}")
    print(f"  board_info offset  : {hdr.board_off}")
    print(f"  product_info offset: {hdr.product_off}")
    print(f"  multirecord offset : {hdr.multirec_off}")
    if hdr.board_off:
        b = parse_board_info(blob, hdr.board_off)
        if b is not None:
            print(f"Board Info           : checksum {'OK' if b.checksum_ok else 'BAD'}")
            mfg = b.mfg_date.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") \
                  if b.mfg_date else "Unspecified"
            print(f"  Mfg date           : {mfg}")
            print(f"  Manufacturer       : {b.manufacturer}")
            print(f"  Product            : {b.product}")
            print(f"  Serial             : {b.serial}")
            print(f"  Part number        : {b.part_number}")
            print(f"  FRU file ID        : {b.fru_file_id}")
            for i, c in enumerate(s for s in b.custom_fields if s):
                print(f"  Custom {i:2}          : {c}")
    if hdr.product_off:
        p = parse_product_info(blob, hdr.product_off)
        if p is not None:
            print(f"Product Info         : checksum {'OK' if p.checksum_ok else 'BAD'}")
            print(f"  Manufacturer       : {p.manufacturer}")
            print(f"  Product Name       : {p.name}")
            print(f"  Part/Model         : {p.part_model}")
            print(f"  Version            : {p.version}")
            print(f"  Serial             : {p.serial}")
            print(f"  Asset Tag          : {p.asset_tag}")
            print(f"  FRU file ID        : {p.fru_file_id}")
            for i, c in enumerate(s for s in p.custom_fields if s):
                print(f"  Custom {i:2}          : {c}")
    return 0


def cmd_mc_selftest(args: argparse.Namespace) -> int:
    with _open_session(args) as s:
        r = s.send_cmd(0x06, 0x04)
    from ..scapy_ipmi.commands import GET_SELF_TEST
    name = GET_SELF_TEST.get(r.result, f"0x{r.result:02x}")
    print(f"Self Test Result : {name}")
    print(f"Info             : 0x{r.info:02x}")
    return 0


def cmd_mc_guid(args: argparse.Namespace) -> int:
    with _open_session(args) as s:
        d = s.send_cmd(0x06, 0x08)
        sy = s.send_cmd(0x06, 0x37)
    print(f"Device GUID : {bytes(d.guid).hex()}")
    print(f"System GUID : {bytes(sy.guid).hex()}")
    return 0


def cmd_chassis_bootdev(args: argparse.Namespace) -> int:
    """Set boot device override via System Boot Options selector 5."""
    devices = list(BOOT_DEVICE.values())
    if args.device == "list":
        print("supported devices:", " ".join(sorted(set(devices))))
        return 0
    if args.device not in devices:
        print(f"unknown device {args.device!r}; try `chassis bootdev list`",
              file=sys.stderr)
        return 2
    if not args.yes and args.device != "no_override":
        print(f"warning: setting boot device to {args.device!r} affects host's "
              f"next boot. Pass --yes to proceed.", file=sys.stderr)
        return 2
    payload = encode_boot_flags(args.device,
                                persistent=args.persistent,
                                uefi=args.uefi)
    with _open_session(args) as s:
        s.send_cmd(0x00, 0x08, SetSystemBootOptionsReq(
            mark_valid=1, parameter_selector=5,
            parameter_data=payload,
        ))
    print(f"boot device override set to {args.device}"
          f"{' (persistent)' if args.persistent else ''}"
          f"{' (UEFI)' if args.uefi else ''}")
    return 0


def cmd_chassis_bootflags(args: argparse.Namespace) -> int:
    """Read current boot flags via Get System Boot Options selector 5."""
    with _open_session(args) as s:
        resp = s.send_cmd(0x00, 0x09, GetSystemBootOptionsReq(
            parameter_selector=5, set_selector=0, block_selector=0,
        ))
    data = bytes(resp.parameter_data)
    if len(data) < 2:
        print(f"empty response: param_rev=0x{resp.parameter_revision:02x}")
        return 1
    valid = bool(data[0] & 0x80)
    persistent = bool(data[0] & 0x40)
    uefi = bool(data[0] & 0x20)
    dev_code = (data[1] >> 2) & 0x0F
    dev = BOOT_DEVICE.get(dev_code, f"unknown_0x{dev_code:x}")
    print(f"valid={valid}  persistent={persistent}  uefi={uefi}  device={dev}")
    return 0


def cmd_chassis_identify(args: argparse.Namespace) -> int:
    """Chassis Identify (NetFn 0x00, Cmd 0x04). Default 15-second blink."""
    with _open_session(args) as s:
        secs = bytes([args.duration]) if args.duration is not None else b""
        cc, _ = s.send_raw(0x00, 0x04, secs)
    if cc != 0:
        print(f"identify: cc=0x{cc:02x}", file=sys.stderr)
        return 1
    if args.duration == 0:
        print("identify off")
    else:
        d = args.duration if args.duration is not None else 15
        print(f"identify on for {d}s")
    return 0


def cmd_lan_print(args: argparse.Namespace) -> int:
    """Print LAN config: IP source, IP, netmask, MAC, gateway.

    Channel defaults to 0x0E ("this channel" — IPMI's self-reference).
    Pass a channel number (0-15) to query a specific LAN channel.
    """
    PARAMS = {
        4:  ("IP Source",      lambda b: {1: "static", 2: "dhcp", 3: "bios", 4: "other"}.get(b[0], f"0x{b[0]:02x}")),
        3:  ("IP Address",     lambda b: ".".join(str(x) for x in b[:4])),
        6:  ("Subnet Mask",    lambda b: ".".join(str(x) for x in b[:4])),
        5:  ("MAC Address",    lambda b: ":".join(f"{x:02x}" for x in b[:6])),
        12: ("Gateway IP",     lambda b: ".".join(str(x) for x in b[:4])),
    }
    channel = int(args.channel, 0) if args.channel is not None else 0x0E
    if not 0 <= channel <= 0x0F:
        print(f"error: channel must be 0..15, got {channel}", file=sys.stderr)
        return 2
    print(f"channel {channel}" + (" (this channel)" if channel == 0x0E else ""))
    with _open_session(args) as s:
        for sel, (label, fmt) in PARAMS.items():
            cc, data = s.send_raw(0x0C, 0x02, bytes([channel, sel, 0, 0]))
            if cc != 0 or len(data) < 2:
                print(f"  {label:14}: cc=0x{cc:02x}")
                continue
            # data[0] = parameter revision, data[1:] = parameter data
            try:
                val = fmt(data[1:])
            except Exception:
                val = data[1:].hex()
            print(f"  {label:14}: {val}")
    return 0


def _read_sdr_record(session, rid: int, record_id: int, total_len: int,
                     chunk: int = 16) -> tuple[int, bytes]:
    """Read a full SDR record in chunks; return (next_record_id, record_bytes).

    Some BMCs (Dell iDRAC6 included) reject count=0xFF on Get SDR with
    CannotReturnRequested. Reading in 16-byte chunks works on every BMC
    we've tested.
    """
    record = b""
    offset = 0
    next_id = 0xFFFF
    # `total_len` already includes the 5 header bytes we passed in via the
    # caller's first read.
    while offset < total_len:
        n = min(chunk, total_len - offset)
        resp = session.send_cmd(
            0x0A, 0x23,
            GetSDRReq(reservation_id=rid, record_id=record_id,
                      offset=offset, count=n),
        )
        record += bytes(resp.record_data)
        next_id = resp.next_record_id
        offset += n
    return next_id, record


def cmd_sensor_list(args: argparse.Namespace) -> int:
    """Sensor list via SDR walk + Get Sensor Reading per sensor.

    For each Type 1 (Full Sensor) and Type 2 (Compact Sensor) SDR, extract
    the sensor number and name, then issue Get Sensor Reading.
    """
    with _open_session(args) as s:
        info = s.send_cmd(0x0A, 0x20)
        if info.record_count == 0:
            print("(no SDR records)")
            return 0
        rsv = s.send_cmd(0x0A, 0x22)
        rid = rsv.reservation_id
        record_id = 0x0000
        seen = 0
        while seen < info.record_count + 4:
            try:
                hdr = s.send_cmd(
                    0x0A, 0x23,
                    GetSDRReq(reservation_id=rid, record_id=record_id,
                              offset=0, count=5),
                )
            except Exception as e:
                print(f"  abort: {e}", file=sys.stderr)
                return 1
            d = bytes(hdr.record_data)
            if len(d) < 5:
                break
            rec_type = d[3]
            length = d[4]
            total_len = 5 + length     # header + body
            next_id = hdr.next_record_id

            if rec_type in (0x01, 0x02):
                next_id, full = _read_sdr_record(s, rid, record_id, total_len)
                # Full sensor record (Type 1) and Compact sensor record (Type 2)
                # share these key offsets:
                #   byte 5  sensor_owner_id
                #   byte 6  sensor_owner_LUN/channel
                #   byte 7  sensor_number
                # The id_string starts at:
                #   Full record    : offset 47 (1 byte type/len + name bytes)
                #   Compact record : offset 31
                if len(full) >= 8:
                    sensor_num = full[7]
                    name_offset = 47 if rec_type == 0x01 else 31
                    name = (full[name_offset + 1:]
                            .rstrip(b"\x00")
                            .decode("utf-8", errors="replace")
                            if len(full) > name_offset + 1
                            else f"sensor_{sensor_num:#x}")
                    try:
                        reading = s.send_cmd(0x04, 0x2D,
                                             GetSensorReadingReq(sensor_number=sensor_num))
                        if reading.status & 0x20:
                            val_str = "n/a"
                        else:
                            val_str = f"raw=0x{reading.reading:02x}"
                    except Exception as e:
                        val_str = f"err={e}"
                    print(f"  0x{sensor_num:02x}  {name:20}  {val_str}")
            seen += 1
            if next_id == 0xFFFF:
                break
            record_id = next_id
    return 0


def cmd_fuzz_rakp(args: argparse.Namespace) -> int:
    """Run the RAKP1 mutation suite against a target.

    Verbosity:
        default       — summary table only.
        -v / --verbose — stream rows as each mutation completes.
        -d / --debug   — same as -v, plus print the raw RAKP2 reply hex.
    """
    from ..fuzz.rakp_mut import fuzz_rakp1
    from ..fuzz.cipher_confuse import RMCP_STATUS
    host = _require_host(args)
    streaming = args.verbose or args.debug
    show_raw = args.debug

    header = (f"  {'mutation':<22}  {'status':<6}  "
              f"{'auth_len':<8}  meaning")

    if streaming:
        print(f"rakp1 fuzz on {host}:{args.port}: (streaming)")
        print(header)

    def _fmt(r: dict) -> str:
        mut = r.get("mutation", "?")
        if "error" in r:
            return f"  {mut:<22}  {'—':<6}  {'—':<8}  [error] {r['error']}"
        if r.get("result") == "timeout":
            return f"  {mut:<22}  {'—':<6}  {'—':<8}  [no reply]"
        if r.get("result") == "no_RAKP2":
            return (f"  {mut:<22}  {'—':<6}  {'—':<8}  "
                    f"non-RAKP2 reply ({r.get('raw_len',0)}B)")
        st = r.get("rmcp_status")
        meaning = RMCP_STATUS.get(st, f"unknown 0x{st:02x}")
        return (f"  {mut:<22}  0x{st:02x}    {r['auth_code_len']:<8}  "
                f"{meaning}")

    def _emit(r: dict) -> None:
        print(_fmt(r), flush=True)
        if show_raw and r.get("reply"):
            print(f"      raw ({len(r['reply'])}B): "
                  f"{r['reply'].hex()}", flush=True)

    results = fuzz_rakp1(
        host=host, port=args.port, user=args.user,
        timeout=args.timeout, on_result=_emit if streaming else None,
    )
    if not streaming:
        print(f"rakp1 fuzz on {host}:{args.port}")
        print(header)
        for r in results:
            print(_fmt(r))
    return 0


def cmd_fuzz_length(args: argparse.Namespace) -> int:
    """IPMI 1.5 msg_length corruption against an active session."""
    from ..fuzz.length import length_corrupt
    netfn = int(args.netfn, 0)
    cmd = int(args.cmd, 0)
    host = _require_host(args)
    with _open_session(args) as s:
        if s.lanplus:
            print("error: length fuzzer requires IPMI 1.5; rerun without -I lanplus",
                  file=sys.stderr)
            return 2
        results = length_corrupt(s, netfn, cmd, b"")
    print(f"length-corrupt cmd 0x{netfn:02x}/0x{cmd:02x} on {host}:")
    print(f"  {'mutation':<12}  {'sent_len':>8}  {'actual':>6}  reply")
    for r in results:
        if r.error:
            tag = f"[error] {r.error}"
        elif r.reply is None:
            tag = "[no reply]"
        else:
            tag = f"{len(r.reply)}B: {r.reply.hex()}"
        print(f"  {r.mutation:<12}  {r.sent_msg_length:>8}  "
              f"{r.actual_ipmb_len:>6}  {tag}")
    return 0


def cmd_fuzz_cipher(args: argparse.Namespace) -> int:
    """RMCP+ cipher-suite negotiation fuzz; pre-auth, no session needed."""
    from ..fuzz.cipher_confuse import cipher_confuse, RMCP_STATUS
    host = _require_host(args)
    results = cipher_confuse(host=host, port=args.port, timeout=args.timeout)
    print(f"cipher-confuse on {host}:{args.port}")
    print(f"  {'mutation':<28}  {'A/I/C':<10}  {'status':<6}  meaning")
    for r in results:
        algs = f"{r.auth_alg:02x}/{r.integrity_alg:02x}/{r.conf_alg:02x}"
        if r.error:
            status_str = "—"
            meaning = f"[error] {r.error}"
        elif r.response_status is None:
            status_str = "—"
            meaning = "[no reply]"
        elif r.session_opened:
            status_str = "0x00"
            meaning = "session opened"
            if r.warning:
                meaning += f"  ⚠ {r.warning}"
        else:
            status_str = f"0x{r.response_status:02x}"
            meaning = RMCP_STATUS.get(r.response_status, "unknown status")
        print(f"  {r.mutation:<28}  {algs:<10}  {status_str:<6}  {meaning}")
    return 0


def cmd_fuzz_list(args: argparse.Namespace) -> int:
    """List the fuzz harnesses zipmi ships."""
    print("zipmi fuzz inventory:")
    print()
    rows = [
        ("sweep",  "wired", "NetFn × Cmd surface enumeration",
         "zipmi.fuzz.sweep"),
        ("rakp",   "wired", "RAKP1 field mutation (pre-auth)",
         "zipmi.fuzz.rakp_mut"),
        ("length", "wired", "IPMI 1.5 msg_length corruption (session)",
         "zipmi.fuzz.length"),
        ("cipher", "wired", "RMCP+ cipher-suite negotiation (pre-auth)",
         "zipmi.fuzz.cipher_confuse"),
    ]
    print(f"  {'verb':<8}  {'state':<6}  {'module':<28}  description")
    for verb, state, desc, mod in rows:
        print(f"  {verb:<8}  {state:<6}  {mod:<28}  {desc}")
    print()
    print("see docs/fuzz-sweep.md and docs/fuzz.md for full coverage notes.")
    return 0


def cmd_fuzz_sweep(args: argparse.Namespace) -> int:
    """Walk every cmd of one NetFn against the target.

    Output verbosity:
        default       — summary only.
        -v / --verbose — stream rows the BMC accepted + skipped rows;
                         omit the (usually huge) cc=0xC1 noise.
        -d / --debug   — stream every probe including 0xC1 InvalidCommand.
    """
    from ..fuzz.sweep import sweep_netfn, summarize
    netfn = int(args.netfn, 0)
    if netfn in (0x30, 0x2E):
        import zipmi
        zipmi.load_vendor("idrac6")

    streaming = args.verbose or args.debug
    show_rejects = args.debug

    if streaming:
        # Header up front so the user sees the column key before rows arrive.
        print(f"sweep NetFn 0x{netfn:02x} on {args.host}: (streaming)")
        print(f"  {'Cmd':>4}  {'CC':>4}  {'len':>3}  "
              f"{'completion code':<55}  name")

    def _emit(r) -> None:
        bucket = r.bucket
        if bucket == "skipped":
            tag = "[skipped]"
            name = _cmd_name(netfn, r.cmd) or "—"
            print(f"  0x{r.cmd:02x}    --    -  "
                  f"{tag:<55}  {name}", flush=True)
            return
        if bucket == "transport_or_parse_error":
            tag = f"[error] {r.error}"
            print(f"  0x{r.cmd:02x}    --    -  {tag:<55}", flush=True)
            return
        if bucket == "bmc_rejected_invalid_cmd":
            if not show_rejects:
                return
            print(f"  0x{r.cmd:02x}  0x{r.cc:02x}  {len(r.body):3d}  "
                  f"{r.cc_name:<55}  —", flush=True)
            return
        # bmc_responded
        name = _cmd_name(netfn, r.cmd) or "—"
        print(f"  0x{r.cmd:02x}  0x{r.cc:02x}  {len(r.body):3d}  "
              f"{r.cc_name:<55}  {name}", flush=True)

    with _open_session(args) as s:
        results = sweep_netfn(
            s, netfn=netfn, rate_hz=args.rate,
            on_result=_emit if streaming else None,
        )
    summary = summarize(results)

    if streaming:
        print()
    print(f"sweep NetFn 0x{netfn:02x} on {args.host}:")
    print(f"  BMC responded            : {len(summary['bmc_responded'])}")
    print(f"  BMC rejected (0xC1)      : "
          f"{len(summary['bmc_rejected_invalid_cmd'])}")
    print(f"  transport/parse errors   : "
          f"{len(summary['transport_or_parse_error'])}")
    print(f"  skipped (destructive)    : {len(summary['skipped'])}")
    return 0


def cmd_sessionless_list(args: argparse.Namespace) -> int:
    """List commands the IPMI 2.0 spec permits outside a session."""
    print("Commands sendable without a session (per IPMI 2.0 spec):")
    print()
    for (netfn, cmd), name in sorted(PRE_SESSION_CMDS.items()):
        print(f"  0x{netfn:02x} 0x{cmd:02x}   {name}")
    print()
    print("Notes:")
    print("""
    To run one of the above, use the "raw" option; e.g.:

        # send a "Get System GUID" request
        $ zipmi -H 192.168.0.23 -P calvin -U root raw 0x06 0x37
    """)
    print("  - The BMC's channel access config may still refuse them.")
    print("  - Run any zipmi verb without -U/-P to send sessionless.")
    print("  - ASF Presence Ping is also pre-session (RMCP class 0x06,")
    print("    not IPMI). Use `zipmi scan asf-ping`.")
    return 0


def cmd_vbmc_serve(args: argparse.Namespace) -> int:
    """Run a virtual BMC on a loopback or specified address."""
    import asyncio
    from ..vbmc.server import run
    trace = 2 if getattr(args, "debug", False) else (
        1 if getattr(args, "verbose", False) else 0)
    color = not getattr(args, "no_color", False)
    palette = getattr(args, "palette", None)
    if palette:
        from ..scapy_ipmi.colorize import (
            normalize_palette_name, resolve_palette, set_palette,
        )
        try:
            set_palette(resolve_palette(normalize_palette_name(palette)))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    try:
        asyncio.run(run(persona_name=args.vpersona,
                        host=args.vbind, port=args.vport,
                        trace=trace, color=color))
    except KeyboardInterrupt:
        print()
    return 0


def cmd_scan_cipher_zero(args: argparse.Namespace) -> int:
    """RMCP+ cipher suite 0 detection.

    Cipher 0 = no auth + no integrity + no conf. If the BMC accepts a
    cipher-0 Open Session (and proceeds through RAKP without checking
    the password), an attacker has full IPMI access without credentials.
    Famous CVE-2013-4786 / Dan Farmer's IPMI WOOT13 paper.
    """
    host = _require_host(args)
    s = Session(
        host=host, username=args.user, password=args.password,
        lanplus=True, cipher_suite=0, timeout=args.timeout,
    )
    s.transport.port = args.port
    _apply_trace(s.transport, args)
    try:
        s.activate()
        print(f"cipher-zero {host}: VULNERABLE — session opened with cipher 0")
        s.close()
        return 0
    except Exception as e:
        print(f"cipher-zero {host}: not vulnerable ({e})")
        s.transport.close()
        return 1


def _cmd_name(netfn: int, cmd: int) -> str:
    """Look up a human-readable name from OEM + base registries."""
    from ..scapy_ipmi.oem._registry import OEM_CMD_NAMES
    from ..scapy_ipmi.commands import CMD_PAYLOADS
    name = OEM_CMD_NAMES.get((netfn, cmd))
    if name:
        return name
    entry = CMD_PAYLOADS.get((netfn, cmd))
    if entry:
        _, resp_cls = entry
        n = resp_cls.__name__
        return n.removesuffix("Resp")
    return ""


def cmd_raw(args: argparse.Namespace) -> int:
    netfn = int(args.netfn, 0)
    cmd = int(args.cmd, 0)
    data = bytes(int(b, 0) & 0xFF for b in args.data)
    # Auto-load iDRAC6 vendor for OEM NetFns so names appear by default.
    if netfn in (0x30, 0x2E):
        import zipmi
        zipmi.load_vendor("idrac6")
    with _open_session(args) as s:
        cc, resp = s.send_raw(netfn, cmd, data)
    cc_name = COMP_CODE.get(cc, f"0x{cc:02x}")
    name = _cmd_name(netfn, cmd)
    if name:
        print(f"# {name}", file=sys.stderr)
    if cc != 0:
        print(f"completion code: {cc_name}", file=sys.stderr)
        return 1
    if resp:
        print(" ".join(f"{b:02x}" for b in resp))
    return 0


def cmd_scan_asf_ping(args: argparse.Namespace) -> int:
    host = _require_host(args)
    pkt = RMCP(msg_class=0x06) / build_ping(msg_tag=0x42)
    # Use Transport (not a bare socket) so -v / -d / colour flags
    # produce a wire trace just like every other verb.
    t = Transport(host=host, port=args.port, timeout=args.timeout)
    _apply_trace(t, args)
    try:
        data = t.send_recv(bytes(pkt))
    except socket.timeout:
        print(f"asf-ping {host}: no reply within {args.timeout}s")
        return 1
    finally:
        t.close()
    reply = RMCP(data)
    asf = reply.getlayer("ASF")
    pong = parse_pong(asf) if asf else None
    if pong is None:
        print(f"asf-ping {host}: reply was not a Pong")
        return 1
    iana = pong.oem_iana
    print(
        f"asf-ping {host}: oem_iana={iana} ({IANA.get(iana, 'unknown')})  "
        f"ipmi={'yes' if pong.supported_entities & 0x80 else 'no'}"
    )
    return 0


def cmd_scan_auth_caps(args: argparse.Namespace) -> int:
    host = _require_host(args)
    t = Transport(host=host, port=args.port, timeout=args.timeout)
    _apply_trace(t, args)
    try:
        _, resp = t.sessionless_request(
            0x06, 0x38, GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4)
        )
    except (OSError, socket.timeout) as e:
        print(f"auth-caps {host}: {e}")
        return 1
    finally:
        t.close()
    if resp is None or resp.comp_code != 0:
        print(f"auth-caps {host}: no decoded reply")
        return 1
    iana = resp.oem_iana_int()
    print(
        f"auth-caps {host}: ch=0x{resp.channel:02x}  "
        f"auth=[{', '.join(resp.auth_types()) or '—'}]  "
        f"status=0x{resp.status:02x}  "
        f"ext=0x{resp.ext_caps:02x}  "
        f"oem_iana={iana} ({IANA.get(iana, 'unknown') if iana else '—'})"
    )
    if resp.auth_type_support & 0x01:
        print(f"  WARNING: 'None' auth advertised — cipher-zero / null-auth risk")
    return 0


def cmd_scan_all(args: argparse.Namespace) -> int:
    rc = 0
    rc |= cmd_scan_asf_ping(args)
    rc |= cmd_scan_auth_caps(args)
    return rc


# -- SOL (Serial Over LAN) ------------------------------------------------

SOL_PRIV = {1: "CALLBACK", 2: "USER", 3: "OPERATOR", 4: "ADMINISTRATOR", 5: "OEM"}


def _sol_get_param(s: Session, channel: int, selector: int) -> bytes | None:
    """Get one SOL config parameter; return its data bytes (param-rev stripped)
    or None if the BMC rejected the selector."""
    cc, data = s.send_raw(0x0C, 0x22, bytes([channel, selector, 0, 0]))
    if cc != 0 or len(data) < 1:
        return None
    return data[1:]                     # data[0] is the parameter revision


def _sol_set_param(s: Session, channel: int, selector: int, data: bytes) -> int:
    """Set one SOL config parameter; return the completion code."""
    cc, _ = s.send_raw(0x0C, 0x21, bytes([channel & 0x0F, selector]) + data)
    return cc


def _sol_channel(args: argparse.Namespace, s: Session | None = None) -> int:
    """Resolve the channel: explicit -> given; else SOL payload channel
    (param 7) if a session is open; else 0x0E ('this channel')."""
    if getattr(args, "channel", None) is not None:
        return int(args.channel, 0)
    if s is not None:
        d = _sol_get_param(s, 0x0E, 7)
        if d:
            return d[0] & 0x0F
    return 0x0E


def _fmt_kbps(baud: int) -> str:
    return f"{baud / 1000:g}"


def cmd_sol_info(args: argparse.Namespace) -> int:
    """Dump SOL configuration parameters, ipmitool `sol info` style."""
    with _open_session(args) as s:
        channel = _sol_channel(args, s)

        sip = _sol_get_param(s, channel, 0)
        en = _sol_get_param(s, channel, 1)
        auth = _sol_get_param(s, channel, 2)
        accum = _sol_get_param(s, channel, 3)
        retry = _sol_get_param(s, channel, 4)
        nv = _sol_get_param(s, channel, 5)
        vol = _sol_get_param(s, channel, 6)
        chan = _sol_get_param(s, channel, 7)
        port = _sol_get_param(s, channel, 8)

    def line(label: str, val) -> None:
        print(f"{label:32}: {val}")

    if sip is not None:
        line("Set in progress",
             {0: "set-complete", 1: "set-in-progress",
              2: "commit-write"}.get(sip[0] & 0x03, f"0x{sip[0]:02x}"))
    if en is not None:
        line("Enabled", "true" if en[0] & 0x01 else "false")
    if auth is not None:
        line("Force Encryption", "true" if auth[0] & 0x80 else "false")
        line("Force Authentication", "true" if auth[0] & 0x40 else "false")
        priv = auth[0] & 0x0F
        line("Privilege Level", SOL_PRIV.get(priv, f"0x{priv:02x}"))
    if accum is not None and len(accum) >= 2:
        line("Character Accumulate Level (ms)", accum[0] * 5)
        line("Character Send Threshold", accum[1])
    if retry is not None and len(retry) >= 2:
        line("Retry Count", retry[0] & 0x07)
        line("Retry Interval (ms)", retry[1] * 10)
    if vol is not None:
        baud = decode_sol_bitrate(vol[0])
        line("Volatile Bit Rate (kbps)",
             _fmt_kbps(baud) if baud else f"code 0x{vol[0] & 0x0F:x}")
    if nv is not None:
        baud = decode_sol_bitrate(nv[0])
        line("Non-Volatile Bit Rate (kbps)",
             _fmt_kbps(baud) if baud else f"code 0x{nv[0] & 0x0F:x}")
    # Param 7 is read-only and unsupported on some BMCs (e.g. iDRAC6);
    # fall back to the resolved channel, mirroring ipmitool.
    pc = chan[0] if chan is not None else channel
    line("Payload Channel", f"{pc} (0x{pc:02x})")
    if port is not None and len(port) >= 2:
        line("Payload Port", port[0] | (port[1] << 8))
    return 0


def cmd_sol_baud(args: argparse.Namespace) -> int:
    """Print just the live SOL baud rate (script-friendly). Reads the
    volatile bit rate (param 6), falling back to non-volatile (param 5)."""
    with _open_session(args) as s:
        channel = _sol_channel(args, s)
        for sel in (6, 5):
            d = _sol_get_param(s, channel, sel)
            if d:
                baud = decode_sol_bitrate(d[0])
                if baud:
                    print(baud)
                    return 0
    print("error: could not read SOL bit rate", file=sys.stderr)
    return 1


def cmd_sol_payload(args: argparse.Namespace) -> int:
    """enable | disable | status — per-user SOL payload access
    (Set/Get User Payload Access, NetFn 0x06 cmd 0x4C/0x4D)."""
    userid = args.userid
    with _open_session(args) as s:
        channel = _sol_channel(args, s)
        if args.op == "status":
            if userid is None:
                userid = 1
            cc, data = s.send_raw(0x06, 0x4D, bytes([channel & 0x0F, userid & 0x3F]))
            if cc != 0 or len(data) < 1:
                print(f"Get User Payload Access: cc=0x{cc:02x}", file=sys.stderr)
                return 1
            enabled = bool(data[0] & 0x02)        # std payload 1 = SOL
            print(f"User {userid} on channel {channel}: "
                  f"SOL payload {'enabled' if enabled else 'disabled'}")
            return 0
        # enable / disable both WRITE config.
        if userid is None:
            print("error: enable/disable require a user id "
                  "(`sol payload enable <channel> <userid>`)", file=sys.stderr)
            return 2
        if not args.yes:
            print(f"warning: '{args.op}' changes SOL access for user {userid}. "
                  f"Pass --yes to proceed.", file=sys.stderr)
            return 2
        operation = 0x00 if args.op == "enable" else (0x01 << 6)
        req = bytes([channel & 0x0F, operation | (userid & 0x3F), 0x02, 0, 0, 0])
        cc, _ = s.send_raw(0x06, 0x4C, req)
    if cc != 0:
        print(f"Set User Payload Access: cc=0x{cc:02x}", file=sys.stderr)
        return 1
    print(f"SOL payload {args.op}d for user {userid} on channel {channel}")
    return 0


def _parse_bitrate_value(v: str) -> int | None:
    """Accept '19.2'/'115.2' (kbps) or '19200'/'9600' (baud) → baud int."""
    v = v.strip().lower().rstrip("k")
    try:
        if "." in v:
            return int(round(float(v) * 1000))
        n = int(v)
        return n if n >= 1000 else n * 1000
    except ValueError:
        return None


def cmd_sol_set(args: argparse.Namespace) -> int:
    """Set a SOL configuration parameter (writes BMC config; --yes gated).

    Multi-field params (authentication, accumulate, retry) are read-modify-
    written so a single field change doesn't clobber the others.
    """
    param = args.parameter
    value = args.value
    if not args.yes:
        print(f"warning: 'sol set {param}' writes BMC SOL config. "
              f"Pass --yes to proceed.", file=sys.stderr)
        return 2

    def truth(v: str) -> bool:
        return v.strip().lower() in ("1", "true", "on", "yes", "enable", "enabled")

    with _open_session(args) as s:
        channel = _sol_channel(args, s)

        if param == "enable":
            cc = _sol_set_param(s, channel, 1, bytes([0x01 if truth(value) else 0x00]))

        elif param in ("force-encryption", "force-authentication", "privilege-level"):
            cur = _sol_get_param(s, channel, 2) or bytes([0x00])
            b = cur[0]
            if param == "force-encryption":
                b = (b | 0x80) if truth(value) else (b & ~0x80)
            elif param == "force-authentication":
                b = (b | 0x40) if truth(value) else (b & ~0x40)
            else:
                names = {v.lower(): k for k, v in SOL_PRIV.items()}
                pv = names.get(value.lower())
                if pv is None:
                    try:
                        pv = int(value, 0)
                    except ValueError:
                        print(f"error: bad privilege level {value!r}", file=sys.stderr)
                        return 2
                b = (b & ~0x0F) | (pv & 0x0F)
            cc = _sol_set_param(s, channel, 2, bytes([b & 0xFF]))

        elif param in ("character-accumulate-level", "character-send-threshold"):
            cur = _sol_get_param(s, channel, 3) or bytes([0x00, 0x00])
            cur = (cur + b"\x00\x00")[:2]
            try:
                n = int(value, 0)
            except ValueError:
                print(f"error: {param} needs an integer", file=sys.stderr)
                return 2
            if param == "character-accumulate-level":
                accum = max(1, round(n / 5)) & 0xFF      # value is ms, units of 5ms
                data = bytes([accum, cur[1]])
            else:
                data = bytes([cur[0], n & 0xFF])
            cc = _sol_set_param(s, channel, 3, data)

        elif param in ("retry-count", "retry-interval"):
            cur = _sol_get_param(s, channel, 4) or bytes([0x00, 0x00])
            cur = (cur + b"\x00\x00")[:2]
            try:
                n = int(value, 0)
            except ValueError:
                print(f"error: {param} needs an integer", file=sys.stderr)
                return 2
            if param == "retry-count":
                data = bytes([n & 0x07, cur[1]])
            else:
                data = bytes([cur[0], (round(n / 10)) & 0xFF])  # value ms, 10ms units
            cc = _sol_set_param(s, channel, 4, data)

        elif param in ("volatile-bit-rate", "non-volatile-bit-rate"):
            baud = _parse_bitrate_value(value)
            code = encode_sol_bitrate(baud) if baud else None
            if code is None:
                print(f"error: unsupported bit rate {value!r} "
                      f"(use 9.6/19.2/38.4/57.6/115.2)", file=sys.stderr)
                return 2
            sel = 6 if param == "volatile-bit-rate" else 5
            cc = _sol_set_param(s, channel, sel, bytes([code & 0x0F]))

        else:
            print(f"error: unknown sol parameter {param!r}", file=sys.stderr)
            return 2

    if cc != 0:
        print(f"sol set {param}: cc=0x{cc:02x}", file=sys.stderr)
        return 1
    print(f"sol set {param} = {value} (channel {channel})")
    return 0


def _require_lanplus_creds(args: argparse.Namespace, verb: str) -> int | None:
    """SOL payloads need an encrypted RMCP+ session. Return an exit code to
    abort, or None if the prerequisites are met."""
    if args.interface != "lanplus":
        print(f"error: 'sol {verb}' requires -I lanplus "
              f"(SOL rides an IPMI 2.0 RMCP+ session)", file=sys.stderr)
        return 2
    if args.user is None or args.password is None:
        print(f"error: 'sol {verb}' requires credentials (-U and -P)",
              file=sys.stderr)
        return 2
    return None


def cmd_sol_activate(args: argparse.Namespace) -> int:
    """Open an interactive SOL console (ipmitool `sol activate`)."""
    rc = _require_lanplus_creds(args, "activate")
    if rc is not None:
        return rc
    from ..sol import SOLConsole
    with _open_session(args) as s:
        return SOLConsole(s).run()


def cmd_sol_deactivate(args: argparse.Namespace) -> int:
    """Deactivate the SOL payload (frees it for another session)."""
    rc = _require_lanplus_creds(args, "deactivate")
    if rc is not None:
        return rc
    from ..scapy_ipmi.commands import DeactivatePayloadReq
    with _open_session(args) as s:
        cc, _ = s.send_raw(0x06, 0x49, bytes(DeactivatePayloadReq(
            payload_type=1, payload_instance=args.instance)))
    if cc == 0x80:
        print("SOL payload already deactivated")
        return 0
    if cc != 0:
        print(f"Deactivate Payload: cc=0x{cc:02x}", file=sys.stderr)
        return 1
    print("SOL payload deactivated")
    return 0


def cmd_sol_looptest(args: argparse.Namespace) -> int:
    """SOL round-trip test (ipmitool `sol looptest`)."""
    rc = _require_lanplus_creds(args, "looptest")
    if rc is not None:
        return rc
    from ..sol import looptest
    with _open_session(args) as s:
        acked, total = looptest(s, iterations=args.iterations,
                                interval=args.interval)
    print(f"SOL looptest: {acked}/{total} packets acknowledged")
    return 0 if acked else 1


def cmd_sol_autobaud(args: argparse.Namespace) -> int:
    """Probe SOL bit rates against the live host serial and apply the rate
    that yields readable output. Catches a host UART whose baud differs from
    the BMC's configured value (the cause of garbled `sol activate`)."""
    rc = _require_lanplus_creds(args, "autobaud")
    if rc is not None:
        return rc
    from ..sol import autobaud
    with _open_session(args) as s:
        channel = _sol_channel(args, s)
        orig = _sol_get_param(s, channel, 6)        # save volatile rate
        results = autobaud(s, channel=channel, dwell=args.dwell)
        best_baud, best_score = (results[0][0], results[0][1]) if results else (None, 0.0)
        applied = None
        if best_baud is not None and best_score >= args.threshold:
            code = encode_sol_bitrate(best_baud)
            s.send_raw(0x0C, 0x21, bytes([channel & 0x0F, 6, code & 0x0F]))
            applied = best_baud
        elif orig:                                  # nothing clean — restore
            s.send_raw(0x0C, 0x21, bytes([channel & 0x0F, 6, orig[0] & 0x0F]))

    for baud, score, sample in results:
        bar = "#" * int(score * 20)
        print(f"  {baud:>6} baud : {score * 100:5.1f}% printable  {bar}")
    if applied is not None:
        print(f"\n=> {applied} baud — set as volatile SOL rate. Now run:")
        print(f"   zipmi -I lanplus -H {args.host} -U {args.user} -P … sol activate")
        return 0
    print("\nno rate produced clean text — host may be idle or powered off. "
          "Try --dwell 5, ensure the host is actively printing, or lower "
          "--threshold.", file=sys.stderr)
    return 1


# -- argparse wiring ------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zipmi",
        description="Scapy-based IPMI client.",
    )
    add_globals(p, suppress=True)

    sub = p.add_subparsers(dest="verb", required=True)

    # mc (bmc = backwards-compat alias, mirrors ipmitool's deprecated "bmc")
    mc = sub.add_parser("mc", aliases=["bmc"], help="management controller")
    mc_sub = mc.add_subparsers(dest="action", required=True)
    mc_info = mc_sub.add_parser("info", help="get device id (manufacturer/firmware)")
    mc_info.set_defaults(func=cmd_mc_info)
    mc_reset = mc_sub.add_parser("reset", help="cold or warm BMC reset")
    mc_reset.add_argument("kind", choices=["cold", "warm"])
    mc_reset.set_defaults(func=cmd_mc_reset)
    mc_st = mc_sub.add_parser("selftest", help="get self test results")
    mc_st.set_defaults(func=cmd_mc_selftest)
    mc_g = mc_sub.add_parser("guid", help="get device + system GUIDs")
    mc_g.set_defaults(func=cmd_mc_guid)
    mc_wd = mc_sub.add_parser("watchdog", help="watchdog timer get/reset/off")
    mc_wd_sub = mc_wd.add_subparsers(dest="wd_action", required=True)
    mc_wdg = mc_wd_sub.add_parser("get", help="read current watchdog state")
    mc_wdg.set_defaults(func=cmd_mc_watchdog_get)
    mc_wdr = mc_wd_sub.add_parser("reset", help="pat the watchdog (Reset cmd)")
    mc_wdr.set_defaults(func=cmd_mc_watchdog_reset)
    mc_wdo = mc_wd_sub.add_parser("off", help="stop the watchdog")
    mc_wdo.add_argument("--yes", action="store_true",
                        help="confirm — disabling the watchdog changes BMC state")
    mc_wdo.set_defaults(func=cmd_mc_watchdog_off)

    # chassis
    ch = sub.add_parser("chassis", help="chassis subsystem")
    ch_sub = ch.add_subparsers(dest="action", required=True)
    ch_status = ch_sub.add_parser("status", help="get chassis status")
    ch_status.set_defaults(func=cmd_chassis_status)
    ch_power = ch_sub.add_parser("power", help="chassis power control")
    ch_power.add_argument("action", choices=list(CHASSIS_CTRL.values()) + ["status"])
    ch_power.add_argument("--yes", action="store_true",
                          help="confirm destructive power action")
    ch_power.set_defaults(func=cmd_chassis_power)
    ch_id = ch_sub.add_parser("identify", help="blink chassis identify LED")
    ch_id.add_argument("duration", type=int, nargs="?", default=15,
                       help="seconds (0 = off; default 15)")
    ch_id.set_defaults(func=cmd_chassis_identify)
    ch_bd = ch_sub.add_parser("bootdev",
                              help="set host boot device (pxe/cd_dvd/hd/...)")
    ch_bd.add_argument("device", help="`list` to see options")
    ch_bd.add_argument("--persistent", action="store_true",
                       help="apply on every subsequent boot, not just next")
    ch_bd.add_argument("--uefi", action="store_true",
                       help="boot in UEFI mode rather than legacy")
    ch_bd.add_argument("--yes", action="store_true",
                       help="confirm setting boot override")
    ch_bd.set_defaults(func=cmd_chassis_bootdev)
    ch_bf = ch_sub.add_parser("bootflags",
                              help="read current boot flags (selector 5)")
    ch_bf.set_defaults(func=cmd_chassis_bootflags)
    ch_rc = ch_sub.add_parser("restart_cause",
                              help="get system restart cause")
    ch_rc.set_defaults(func=cmd_chassis_restart_cause)
    ch_pp = ch_sub.add_parser("policy", help="get/set power restore policy")
    ch_pp.add_argument("policy",
                       choices=["list", "always-off", "previous", "always-on"],
                       help="'list' queries supported; others set the policy")
    ch_pp.set_defaults(func=cmd_chassis_policy)

    # sel
    sel = sub.add_parser("sel", help="system event log")
    sel_sub = sel.add_subparsers(dest="action", required=True)
    sel_info = sel_sub.add_parser("info", help="SEL repository info")
    sel_info.set_defaults(func=cmd_sel_info)
    sel_list = sel_sub.add_parser("list", help="walk and decode SEL entries")
    sel_list.set_defaults(func=cmd_sel_list)
    sel_elist = sel_sub.add_parser(
        "elist",
        help="extended SEL list — SDR-resolved sensor names + decoded events",
    )
    sel_elist.set_defaults(func=cmd_sel_elist)
    sel_clear = sel_sub.add_parser("clear", help="erase all SEL entries")
    sel_clear.set_defaults(func=cmd_sel_clear)
    sel_time = sel_sub.add_parser("time", help="get/set BMC SEL clock")
    sel_time_sub = sel_time.add_subparsers(dest="time_action", required=True)
    sel_tg = sel_time_sub.add_parser("get", help="read current SEL time")
    sel_tg.set_defaults(func=cmd_sel_time_get)
    sel_ts = sel_time_sub.add_parser("set", help="set SEL time")
    sel_ts.add_argument("timestamp",
                        help="'now' or seconds-since-1970-UTC (decimal or 0x...)")
    sel_ts.set_defaults(func=cmd_sel_time_set)

    # sdr
    sdr = sub.add_parser("sdr", help="sensor data records")
    sdr_sub = sdr.add_subparsers(dest="action", required=True)
    sdr_list = sdr_sub.add_parser("list", help="walk SDR repository")
    sdr_list.set_defaults(func=cmd_sdr_list)

    # sensor
    sn = sub.add_parser("sensor", help="sensor readings")
    sn_sub = sn.add_subparsers(dest="action", required=True)
    sn_list = sn_sub.add_parser("list", help="walk SDR + read each sensor")
    sn_list.set_defaults(func=cmd_sensor_list)

    # lan
    lan = sub.add_parser("lan", help="LAN configuration")
    lan_sub = lan.add_subparsers(dest="action", required=True)
    lan_print = lan_sub.add_parser("print", help="show IP/MAC/gateway/source")
    lan_print.add_argument("channel", nargs="?", default=None,
                           help="channel number 0..15 (default 0x0E "
                                "= 'this channel'); accepts decimal or 0x hex")
    lan_print.set_defaults(func=cmd_lan_print)

    # sol (Serial Over LAN)
    SOL_SET_PARAMS = [
        "enable", "force-encryption", "force-authentication", "privilege-level",
        "character-accumulate-level", "character-send-threshold",
        "retry-count", "retry-interval",
        "volatile-bit-rate", "non-volatile-bit-rate",
    ]
    sol = sub.add_parser("sol", help="serial over LAN")
    sol_sub = sol.add_subparsers(dest="action", required=True)
    sol_info = sol_sub.add_parser("info", help="dump SOL configuration parameters")
    sol_info.add_argument("channel", nargs="?", default=None,
                          help="channel (default = SOL payload channel)")
    sol_info.set_defaults(func=cmd_sol_info)
    sol_baud = sol_sub.add_parser("baud", help="print live SOL baud (script-friendly)")
    sol_baud.add_argument("channel", nargs="?", default=None)
    sol_baud.set_defaults(func=cmd_sol_baud)
    sol_pl = sol_sub.add_parser("payload", help="per-user SOL payload access")
    sol_pl.add_argument("op", choices=["enable", "disable", "status"])
    sol_pl.add_argument("channel", nargs="?", default=None)
    sol_pl.add_argument("userid", nargs="?", type=int, default=None)
    sol_pl.add_argument("--yes", action="store_true",
                        help="confirm enable/disable (writes config)")
    sol_pl.set_defaults(func=cmd_sol_payload)
    sol_set = sol_sub.add_parser("set", help="set a SOL configuration parameter")
    sol_set.add_argument("parameter", choices=SOL_SET_PARAMS)
    sol_set.add_argument("value")
    sol_set.add_argument("channel", nargs="?", default=None)
    sol_set.add_argument("--yes", action="store_true",
                         help="confirm write to BMC SOL config")
    sol_set.set_defaults(func=cmd_sol_set)
    sol_act = sol_sub.add_parser("activate",
                                 help="open interactive SOL console (needs -I lanplus)")
    sol_act.set_defaults(func=cmd_sol_activate)
    sol_deact = sol_sub.add_parser("deactivate", help="deactivate the SOL payload")
    sol_deact.add_argument("--instance", type=int, default=1,
                           help="payload instance (default 1)")
    sol_deact.set_defaults(func=cmd_sol_deactivate)
    sol_loop = sol_sub.add_parser("looptest", help="SOL round-trip test")
    sol_loop.add_argument("iterations", nargs="?", type=int, default=10)
    sol_loop.add_argument("interval", nargs="?", type=float, default=0.1)
    sol_loop.set_defaults(func=cmd_sol_looptest)
    sol_ab = sol_sub.add_parser(
        "autobaud",
        help="probe bit rates against live host serial; apply the readable one")
    sol_ab.add_argument("channel", nargs="?", default=None)
    sol_ab.add_argument("--dwell", type=float, default=2.5,
                        help="seconds to sample per rate (default 2.5)")
    sol_ab.add_argument("--threshold", type=float, default=0.7,
                        help="min printable ratio to accept (default 0.7)")
    sol_ab.set_defaults(func=cmd_sol_autobaud)

    # user
    user = sub.add_parser("user", help="user accounts")
    user_sub = user.add_subparsers(dest="action", required=True)
    user_list = user_sub.add_parser("list", help="list users via Get User Access/Name")
    user_list.set_defaults(func=cmd_user_list)
    user_set = user_sub.add_parser("set", help="set username or password")
    user_set_sub = user_set.add_subparsers(dest="set_action", required=True)
    user_set_name = user_set_sub.add_parser("name", help="Set User Name")
    user_set_name.add_argument("user_id", type=int)
    user_set_name.add_argument("name")
    user_set_name.add_argument("--yes", action="store_true",
                               help="confirm BMC user-table modification")
    user_set_name.set_defaults(func=cmd_user_set_name)
    user_set_pw = user_set_sub.add_parser("password", help="Set User Password")
    user_set_pw.add_argument("user_id", type=int)
    user_set_pw.add_argument("new_password", metavar="password")
    user_set_pw.add_argument("size", nargs="?", type=int, default=16,
                             choices=[16, 20],
                             help="password slot size (16 or 20 bytes)")
    user_set_pw.add_argument("--yes", action="store_true",
                             help="confirm BMC user-table modification")
    user_set_pw.set_defaults(func=cmd_user_set_password)
    user_en = user_sub.add_parser("enable", help="enable user (op 1)")
    user_en.add_argument("user_id", type=int)
    user_en.add_argument("--yes", action="store_true")
    user_en.set_defaults(func=cmd_user_enable, size=16)
    user_dis = user_sub.add_parser("disable", help="disable user (op 0)")
    user_dis.add_argument("user_id", type=int)
    user_dis.add_argument("--yes", action="store_true")
    user_dis.set_defaults(func=cmd_user_disable, size=16)
    user_test = user_sub.add_parser("test", help="test password (op 3, read-only)")
    user_test.add_argument("user_id", type=int)
    user_test.add_argument("test_password", metavar="password")
    user_test.add_argument("size", nargs="?", type=int, default=16,
                           choices=[16, 20])
    user_test.set_defaults(func=cmd_user_test_password)
    user_priv = user_sub.add_parser("priv", help="Set User Access privilege")
    user_priv.add_argument("user_id", type=int)
    user_priv.add_argument("level", choices=list(PRIV_LEVELS.keys()))
    user_priv.add_argument("channel", nargs="?", type=lambda s: int(s, 0),
                           default=0x0E,
                           help="channel number (default 0x0E = this channel)")
    user_priv.add_argument("--yes", action="store_true")
    user_priv.set_defaults(func=cmd_user_priv)

    # channel
    chn = sub.add_parser("channel", help="channel info + access")
    chn_sub = chn.add_subparsers(dest="action", required=True)
    chn_info = chn_sub.add_parser("info", help="Get Channel Info")
    chn_info.add_argument("channel", nargs="?", type=lambda s: int(s, 0),
                          default=0x0E,
                          help="channel number (default 0x0E = this channel)")
    chn_info.set_defaults(func=cmd_channel_info)
    chn_ga = chn_sub.add_parser("getaccess", help="Get User Access on a channel")
    chn_ga.add_argument("channel", type=lambda s: int(s, 0))
    chn_ga.add_argument("user_id", type=int)
    chn_ga.set_defaults(func=cmd_channel_getaccess)

    # session
    sess = sub.add_parser("session", help="session info")
    sess_sub = sess.add_subparsers(dest="action", required=True)
    sess_info = sess_sub.add_parser("info",
                                    help="Get Session Info (default: active)")
    sess_info.add_argument("selector", nargs="?", default="active",
                           help="'active' or session index (decimal or 0x...)")
    sess_info.set_defaults(func=cmd_session_info)

    # fru
    fru = sub.add_parser("fru", help="FRU inventory")
    fru_sub = fru.add_subparsers(dest="action", required=True)
    fru_p = fru_sub.add_parser("print", help="dump FRU device contents")
    fru_p.add_argument("device_id", nargs="?", type=lambda s: int(s, 0),
                       default=0, help="FRU device ID (default 0)")
    fru_p.set_defaults(func=cmd_fru_print)

    # raw
    raw = sub.add_parser("raw", help="send arbitrary NetFn/Cmd/Data")
    raw.add_argument("netfn")
    raw.add_argument("cmd")
    raw.add_argument("data", nargs="*")
    raw.set_defaults(func=cmd_raw)

    # OEM verbs: `zipmi oem` + per-vendor shortcuts (dell, supermicro, ...).
    from .oem_cmds import add_oem_subparsers
    add_oem_subparsers(sub)

    # Group Extension verbs: `zipmi groups` + per-body shortcuts (dcmi, ...).
    from .groups_cmds import add_groups_subparsers
    add_groups_subparsers(sub)

    # fuzz
    fz = sub.add_parser("fuzz", help="fuzzing / sweep harness")
    fz_sub = fz.add_subparsers(dest="action", required=True)
    fz_sweep = fz_sub.add_parser("sweep", help="walk every cmd of one NetFn")
    fz_sweep.add_argument("--netfn", default="0x06", help="NetFn to sweep")
    fz_sweep.add_argument("--rate", type=float, default=10.0,
                          help="probe rate in Hz (default 10)")
    fz_sweep.set_defaults(func=cmd_fuzz_sweep)
    fz_rakp = fz_sub.add_parser("rakp", help="RAKP1 field mutation suite")
    fz_rakp.set_defaults(func=cmd_fuzz_rakp)
    fz_len = fz_sub.add_parser("length",
                               help="IPMI 1.5 msg_length corruption")
    fz_len.add_argument("--netfn", default="0x06", help="NetFn (default 0x06)")
    fz_len.add_argument("--cmd", default="0x01", help="Cmd (default 0x01 GetDeviceID)")
    fz_len.set_defaults(func=cmd_fuzz_length)
    fz_ciph = fz_sub.add_parser("cipher",
                                help="RMCP+ cipher-suite negotiation fuzz")
    fz_ciph.set_defaults(func=cmd_fuzz_cipher)
    fz_list = fz_sub.add_parser("list",
                                help="enumerate available fuzzers + status")
    fz_list.set_defaults(func=cmd_fuzz_list)

    # vbmc
    vb = sub.add_parser("vbmc", help="virtual BMC server")
    vb_sub = vb.add_subparsers(dest="action", required=True)
    vb_serve = vb_sub.add_parser("serve", help="run a virtual BMC")
    vb_serve.add_argument("--vpersona", dest="vpersona", default="generic",
                          help="generic | dell_idrac6 (default generic)")
    vb_serve.add_argument("--vbind", dest="vbind", default="127.0.0.1",
                          help="bind address (default 127.0.0.1)")
    vb_serve.add_argument("--vport", dest="vport", type=int, default=6230,
                          help="vBMC UDP listen port (default 6230)")
    vb_serve.set_defaults(func=cmd_vbmc_serve)

    # scan
    # sessionless — list pre-session commands per IPMI 2.0 spec
    sl = sub.add_parser(
        "sessionless",
        help="list commands spec-permitted outside a session",
    )
    sl.set_defaults(func=cmd_sessionless_list)

    sc = sub.add_parser("scan", help="sessionless probes")
    sc_sub = sc.add_subparsers(dest="action", required=True)
    for name, fn in [("asf-ping", cmd_scan_asf_ping),
                     ("auth-caps", cmd_scan_auth_caps),
                     ("cipher-zero", cmd_scan_cipher_zero),
                     ("all", cmd_scan_all)]:
        s = sc_sub.add_parser(name)
        s.set_defaults(func=fn)

    return p


def main(argv: list[str] | None = None) -> int:
    args = parse_cli(argv)
    try:
        return args.func(args)
    except IPMIError as e:
        print(f"IPMI error: {e}", file=sys.stderr)
        return 1
    except (OSError, socket.timeout) as e:
        print(f"transport error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
