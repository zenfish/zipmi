#!/usr/bin/env python3
"""
00_asf_ping.py — ASF Presence Ping/Pong smoke test.

WHAT     Sends a single ASF Presence Ping (DSP0136) to a BMC over UDP/623
         and decodes the Pong reply, printing the OEM IANA Enterprise
         Number and the IPMI-support bit.

WHY      Phase 0 verification that the RMCP and ASF Scapy layers correctly
         build and parse traffic against a real BMC. No IPMI session
         required — pure discovery probe.

SUCCESS  Against a BMC that honors ASF Ping:
            $ python examples/00_asf_ping.py <bmc-ip>
            Pong from <ip>  oem_iana=<iana> (<vendor>)  ipmi=True

         NOTE: Dell iDRAC6 does NOT reply to ASF Ping by default (see
         docs/ipmi15-notes.md). Wire bytes are correct per DSP0136; the
         BMC silently drops the packet. Use a Supermicro/HP target, or
         (Phase 1+) the `Get Channel Auth Caps` sessionless probe.

TARGET   Any RMCP/UDP-623 endpoint implementing DSP0136. Wire format
         verified against Dell PowerEdge T710 / iDRAC6 via tcpdump.

BUILD    pip install -e .  (from the zipmi repo root)
RUN      python examples/00_asf_ping.py <bmc-ip> [timeout-seconds]
EXIT     0 on Pong received; 1 on timeout; 2 on usage error.

RELATED  zipmi/scapy_ipmi/rmcp.py, zipmi/scapy_ipmi/asf.py,
         /Users/zen/phd/dox/specs/DSP0136.pdf §3.2.4
"""

from __future__ import annotations

import socket
import sys

import zipmi  # noqa: F401  (registers Scapy layers as a side effect)
from scapy.packet import Raw

from zipmi.consts import IANA
from zipmi.scapy_ipmi.asf import ASF, build_ping, parse_pong
from zipmi.scapy_ipmi.rmcp import RMCP


def asf_ping(target: str, timeout: float = 2.0) -> ASF | None:
    """Send a Presence Ping and return the parsed Pong ASF header, or None."""
    pkt = RMCP(msg_class=0x06) / build_ping(msg_tag=0x42)
    wire = bytes(pkt)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(wire, (target, 623))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            return None

    reply = RMCP(data)
    if not reply.haslayer(ASF):
        return None
    return reply[ASF]


def main(argv: list[str]) -> int:
    if len(argv) < 2 or len(argv) > 3:
        print(f"usage: {argv[0]} <bmc-ip> [timeout-seconds]", file=sys.stderr)
        return 2
    target = argv[1]
    timeout = float(argv[2]) if len(argv) == 3 else 2.0

    asf = asf_ping(target, timeout=timeout)
    if asf is None:
        print(f"timeout: no Pong from {target} within {timeout}s", file=sys.stderr)
        return 1

    if asf.msg_type != 0x40:
        print(f"unexpected ASF reply: msg_type=0x{asf.msg_type:02x}", file=sys.stderr)
        # Show what we got anyway.
        asf.show()
        return 1

    pong = parse_pong(asf)
    if pong is None:
        print("Pong reply had no body — short packet?", file=sys.stderr)
        return 1

    vendor = IANA.get(pong.oem_iana, "unknown")
    ipmi_bit = bool(pong.supported_entities & 0x80)
    print(
        f"Pong from {target}  "
        f"oem_iana={pong.oem_iana} ({vendor})  "
        f"ipmi={ipmi_bit}  "
        f"entities=0x{pong.supported_entities:02x}  "
        f"interactions=0x{pong.supported_interactions:02x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
