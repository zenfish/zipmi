# Using zipmi as a Scapy library

zipmi models IPMI commands as **Scapy `Packet` classes** — every wire field is a
real, named Scapy field you can set, read, dissect, and fuzz. This is what the
**✓** mark in [command-table.md](command-table.md) means: a paired request/response
packet class registered in `CMD_PAYLOADS`, usable programmatically (not just from
the CLI).

## What's supported

- **✓ in `command-table.md`** = a Scapy packet class (`zipmi.scapy_ipmi.commands`),
  registered in `CMD_PAYLOADS[(netfn, cmd)] = (ReqClass, RespClass)`. Full
  field-level encode/decode; drivable via `session.send_cmd()`.
- **⚡** = a CLI verb only (decodes in the handler via `send_raw`). Works from the
  CLI with structured output, but **no packet class** — not usable via `send_cmd`,
  not fuzzable at the field level.

The authoritative ✓ list is the `zipmi` column of `command-table.md`. Bus /
motherboard-component commands (I2C, FRU, NIC/LAN, serial, sensor) are being
promoted ⚡→✓ first — see [firmware-and-bus-access.md](firmware-and-bus-access.md).

## Driving a command programmatically

```python
import zipmi                       # registers all base Scapy layers
from zipmi.core import Session
from zipmi.scapy_ipmi.commands import MasterWriteReadReq

with Session(host="10.0.0.5", username="ADMIN", password="ADMIN",
             lanplus=True) as s:
    # Build the request as a packet — named fields, no hand-packed bytes.
    req = MasterWriteReadReq(channel=0, private=0, slave_addr=0x50,
                             read_count=16, write_data=b"\x00")   # SPD @ 0x50
    resp = s.send_cmd(0x06, 0x52, req)      # -> a decoded MasterWriteReadResp
    print(resp.comp_code, bytes(resp.read_data).hex())
```

`send_cmd(netfn, cmd, req_packet)` looks up `CMD_PAYLOADS`, sends the request
bytes, and returns the **decoded response packet** (raises `IPMIError` on a
non-zero completion code — use `send_raw` when you want the raw `(cc, bytes)` and
no exception, e.g. probing where rejects are expected).

## Inspect / dissect / fuzz

```python
from zipmi.scapy_ipmi.commands import MasterWriteReadReq, MasterWriteReadResp

MasterWriteReadReq(slave_addr=0x50).show()      # pretty field dump
bytes(MasterWriteReadReq(channel=1, private=1, priv_bus=2,
                         slave_addr=0x50, read_count=8))   # -> b'\x15\xa0\x08'

# Dissect bytes off the wire:
MasterWriteReadResp(b"\x00\xde\xad\xbe\xef").read_data     # b'\xde\xad\xbe\xef'

# Fuzz a single field — every field is settable, so mutation is trivial:
for addr in range(0x00, 0x80):
    probe = MasterWriteReadReq(slave_addr=addr, read_count=1)
    # ... send bytes(probe), watch for a non-0xC1 reply
```

Because the fields are real Scapy fields, the `fuzz` harness can mutate them by
name, and the wire trace (`-d`) shows decoded fields instead of raw hex.

## Adding a command (⚡→✓)

1. Define `XReq(Packet)` and `XResp(Packet)` in `zipmi/scapy_ipmi/commands.py`
   with `fields_desc` matching the spec wire layout (use `BitField` for
   sub-byte fields so they stay individually fuzzable). Add
   `def extract_padding(self, s): return b"", s`.
2. Register `(netfn, cmd): (XReq, XResp)` in `CMD_PAYLOADS`.
3. Point the CLI handler at the class (`bytes(XReq(...))` for the request, or
   `send_cmd` for the decoded response) so CLI and library share one model.
4. Flip the `command-table.md` row ⚡→✓ and add a `tests/unit/test_scapy_bus.py`
   case asserting the wire bytes.
