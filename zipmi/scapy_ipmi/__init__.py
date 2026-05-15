"""
zipmi.scapy_ipmi — Scapy layer registration.

WHAT     Importing this subpackage registers RMCP and its sub-protocols
         (ASF, IPMI 1.5, IPMI 2.0, RAKP) as Scapy layers and binds them
         under UDP/623.
WHY      Centralise `bind_layers` calls so the order of registration is
         deterministic regardless of which submodule the caller imports first.
SUCCESS  `from scapy.all import UDP; UDP(dport=623, payload=b"\\x06\\x00\\xff\\x07")`
         dissects to UDP/RMCP/IPMI15_Session.
TARGET   Scapy >= 2.6.
RELATED  rmcp.py, asf.py
"""

from __future__ import annotations

# Side-effect imports register Packet classes + bind_layers calls.
from . import rmcp     # noqa: F401
from . import asf      # noqa: F401
from . import ipmi15   # noqa: F401  (IPMI 1.5 Session + Message)
from . import ipmi20   # noqa: F401  (IPMI 2.0 RMCP+ Session)
from . import rakp     # noqa: F401  (Open Session + RAKP 1-4)
from . import commands # noqa: F401  (per-cmd Packet classes + registry)

__all__ = ["rmcp", "asf", "ipmi15", "ipmi20", "rakp", "commands"]
