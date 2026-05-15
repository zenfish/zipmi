# IPMI 1.5 — implementation notes & target quirks

Running notes on quirks observed during implementation. Capture-everything
style — better to over-document than to re-discover the same gotcha twice.

## Gotcha: RMCP Message Class for ASF is 6, not 0

Some online references (and an early version of this codebase) say RMCP
class field 0 is ASF. **It isn't.** Per RFC 4413 / IPMI 1.5 §13.1.3 /
DSP0136 §3.2.2, classes 0–5 are reserved; 6 = ASF; 7 = IPMI. iDRAC6
silently drops a Presence Ping with class=0; with class=6 it replies as
expected. Cost us about ten minutes in Phase 0; documented to save the
next person the same head-scratch.

## Dell iDRAC6 (PowerEdge T710, FW 1.70)

### Reports IPMI Version 2.0 but commonly run as 1.5 in the field

`ipmitool mc info` returns `IPMI Version: 2.0`, but most prior research and
client tooling targets this device with IPMI 1.5 / `-I lan`. Dell did
implement RMCP+ in iDRAC6 firmware later, but cipher-suite support is
limited; verify with `Get Channel Cipher Suites` once we ship that command.
