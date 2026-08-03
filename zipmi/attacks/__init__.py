"""zipmi.attacks — named attack primitives ingested from prior research.

Each module under here corresponds to a vendor + research thread. Loaders
are explicit (no auto-import); call e.g. `zipmi.attacks.dell.PROCHOT.send(s)`
to fire a documented attack against an active Session.

WHY      Centralises the "attacks I've previously demonstrated" surface
         so I don't have to remember byte sequences across sessions.
RELATED  zipmi/scapy_ipmi/oem/*, Dell iDRAC OEM RE notes (attack analyses)
"""
