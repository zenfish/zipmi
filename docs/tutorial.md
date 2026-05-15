# zipmi tutorial

A walkthrough modelled on the [Scapy
tutorial](https://scapy.readthedocs.io/en/latest/usage.html). You'll
build IPMI packets in the REPL, send them at a real BMC, and inspect
the bytes that come back. By the end you'll be able to drop into a
session and ask *what does this byte mean?* about any field on the
wire.

## Prerequisites

```bash
make install                         # from the zipmi repo root
export ZIPMI_TARGET=192.168.0.23     # BMC IP
export ZIPMI_USER=root
export ZIPMI_PASS=calvin
```

`tcpdump`, `wireshark`, and `ipmitool` are useful sidecars but not
required.

For the in-CLI equivalent of a hex dump, every BMC-talking verb takes
`-v` (work packets only) or `-d` (work + setup). Each line shows the
IPMI Table G-1 command name plus the wire bytes colour-coded by field
(NetFn, cmd, data, completion code, ...). See the **Wire trace**
section of the README for palette and `--no-color` options.

To skip the hex entirely and just call OEM commands by name, use the
vendor verbs: `zipmi idrac6 GetChassisStatus`, `zipmi supermicro
StartRestore`, `zipmi idrac9 OemSensorTest` etc. `zipmi oem` (no
args) lists known vendors; `zipmi <vendor>` (no args) lists that
vendor's catalogue with NetFn / cmd / privilege / description.

Each catalogue is sourced differently:

- **idrac6**: 195 names binary-RE'd from `T710-bmc/bin/fullfw` with
  radare2; the rest of the dispatch table (~190 entries) keeps
  privilege + description metadata from the human MD analysis. See
  `~/phd/bmc/dell/fullfw-dispatch-binary.md` for the raw dump.
- **idrac9**: 349 known dispatch slots (271 static + 78 runtime-only),
  **277 named**. Three resolution layers: 46 from the upstream RE doc,
  99 from dynsym DF .text addr resolution (handler addresses point
  straight at exported `Cmd*` symbols), and 132 from R_ARM_GLOB_DAT
  relocation extraction (every lib has `.data`-section dispatch
  arrays whose handler-pointer slots are relocations resolved at
  load; pair the relocation symbol with the descriptor 4 bytes before
  the slot and you recover (NetFn, cmd) → handler). The remaining
  72 slots are bound at boot via init-agent paths invisible to static
  analysis; they keep their dispatch-table tag (DCMI / OEMIPMI /
  OSAOEM) for fuzzing targets.
- **supermicro**: 4 top-level dispatchers + 61 sub-cmds from the
  smcipmi RE work. Sub-cmds are listed as 3-byte tuples like
  `0x30 0x70 0x12 OEMFlashFWCmd` and zipmi prepends the sub byte
  automatically when you call by name.

The IANA Private Enterprise Number printed beside each vendor in
`zipmi oem` is the disambiguator that makes "OEM by name" possible.
OEM NetFns are a private namespace per vendor — `(0x30, 0xC0)` is
PROCHOT throttle on Dell, a different cmd on Supermicro. The target's
IANA appears in `Get Device ID`'s manufacturer-ID field and the ASF
Pong reply, both pre-auth. So the workflow is: `zipmi scan asf-ping
<bmc>` (or `mc info`) → read the IANA → pick the matching `zipmi
<vendor>` table.

## A bird's-eye view of the layers

Every IPMI-over-LAN packet looks like this on the wire:

```
UDP(623) → RMCP →┬→ ASF_PresencePing/Pong          (DSP0136 — discovery)
                 ├→ IPMI15_Session → IPMI_Message → <CmdPayload>
                 └→ IPMI20_Session →┬→ RAKP1/2/3/4
                                    └→ encrypted IPMI_Message
```

Each box is a Scapy `Packet` class. Stack them with `/`, serialize
with `bytes()`, dissect by passing bytes to a class.

## 1. Build your first packet — an ASF Ping

ASF Ping is the simplest IPMI-adjacent probe. No session, no auth,
no encryption — twelve bytes of header.

```pycon
>>> import zipmi  # registers all layers as a side effect
>>> from zipmi.scapy_ipmi.rmcp import RMCP
>>> from zipmi.scapy_ipmi.asf import ASF, build_ping, parse_pong

>>> ping = RMCP(msg_class=0x06) / build_ping(msg_tag=0x42)
>>> ping.show()
###[ RMCP ]###
  version   = 6
  reserved  = 0
  seq       = 255
  ack       = 0
  class_reserved= 0
  msg_class = ASF
###[ ASF ]###
     iana      = 4542
     msg_type  = PresencePing
     msg_tag   = 66
     reserved  = 0
     data_length= None
     data      = b''
```

`data_length= None` is not a bug — `data_length` is a
`FieldLenField(length_of="data")`, so its value is **computed at
serialization time**, not when you construct the packet. `.show()`
shows the *unbuilt* view, where the length is still unresolved
(`None`). Serialize and it materializes:

```pycon
>>> bytes(ping).hex()
'0600ff06000011be80420000'
>>> RMCP(bytes(ping))[ASF].data_length      # round-trip → resolved
0
```

That's the byte-exact 12-byte DSP0136 §3.2.4.1 frame: `0600ff06`
(RMCP) + `000011be` (ASF IANA 4542) + `80` (PresencePing) + `42`
(tag) + `00` (reserved) + `00` (data_length, now computed).

> Aside: in the REPL, type `ping.show()` — not `print(ping.show())`.
> `.show()` prints as a side effect and returns `None`, so wrapping it
> in `print()` tacks a stray `None` onto the output. (Same for
> `.show2()`, `ls()`, `hexdump()`.)

## 2. Send it and parse the Pong — the scapy way

The `ping` from §1 stops at RMCP. To put it on the wire, wrap it in
the IP/UDP that scapy will route, then use `sr1()` — "send one packet,
receive one reply" — the scapy workhorse from the
[usage tutorial](https://scapy.readthedocs.io/en/latest/usage.html).

```pycon
>>> from scapy.all import IP, UDP, sr1, conf
>>> conf.verb = 0                       # silence scapy's own send/recv banner

>>> pkt = IP(dst="192.168.0.23") / UDP(dport=623) / ping
>>> pkt.summary()
'IP / UDP 192.168.0.2:asf_rmcp > 192.168.0.23:asf_rmcp / RMCP / ASF'

>>> reply = sr1(pkt, timeout=3)
>>> reply.summary()
'IP / UDP 192.168.0.23:asf_rmcp > 192.168.0.2:asf_rmcp / RMCP / ASF'
```

No socket, no `recvfrom`, no length juggling. `sr1()` serialized the
stack, matched the reply to the request, and handed it back **already
dissected** all the way down — because `rmcp.py` did
`bind_layers(UDP, RMCP, dport=623)` and `asf.py` bound ASF under RMCP.
The bind is bidirectional, so the *reply* parses too. Reach in by
layer:

```pycon
>>> pong = parse_pong(reply[ASF])
>>> pong.show()
###[ ASF Presence Pong ]###
  oem_iana  = 4542
  oem_defined= 0
  supported_entities= 0x81
  supported_interactions= 0x0
  reserved1 = 0
  ...
>>> hex(pong.supported_entities), bool(pong.supported_entities & 0x80)
('0x81', True)
```

`supported_entities` bit 7 (`0x80`) means this BMC speaks IPMI; bit 0
(`0x01`) means it implements ASF v1.0. So `0x81` = both.

Other scapy verbs that work on these packets unchanged: `send(pkt)`
(fire-and-forget, no reply wanted), `sr(pkt)` (keep *all* replies, not
just the first), `hexdump(reply)` (annotated bytes), `ls(ASF)` (field
table), `sniff(filter="udp port 623", prn=lambda p: p.summary())`
(passive capture). Everything in the scapy tutorial applies because
these are real scapy `Packet`s, not custom blobs.

> **`sr1()` builds at layer 3**, so it needs raw-socket privileges
> (root, `cap_net_raw`, or BPF access on macOS). That's the price of
> letting scapy own the IP/UDP layer. The next section shows the rung
> *below* this — where you trade scapy's routing for an ordinary
> unprivileged UDP socket and zipmi drives the bytes itself.

The same probe is built into the CLI:

```bash
$ zipmi scan asf-ping
asf-ping 192.168.0.23: oem_iana=4542 (ASF) ipmi=yes
```

## 3. Slipping between scapy, zipmi, and sockets

zipmi is built as a ladder of abstractions. You climb up for
convenience, drop down for control, and the rung you step off at is
entirely up to the task — the bytes are identical at every level.

| Rung | Tool | You own | Good for |
| ---- | ---- | ------- | -------- |
| **scapy L3** | `sr1()` / `send()` / `sniff()` | nothing — scapy routes IP/UDP | one-shot probes, captures, fuzz spray (needs root) |
| **scapy bytes** | `bytes(pkt)` / `RMCP(data)` | the socket | full wire control, unprivileged UDP, custom matching |
| **zipmi Transport** | `Transport.send_recv()` | one connected UDP socket | sessionless requests, source-port pinning |
| **zipmi Session** | `Session.send_cmd()` | auth + seq + session state | authenticated work, the boring 99% |

Why zipmi's own I/O lives at the **scapy-bytes** rung and not on
`sr1()`: the scapy layers are kept deliberately I/O-free so they stay
trivially fuzzable and testable against the `vbmc` fixture with no
network at all (see `core.py`'s module docstring). On top of that,
`Transport` needs an *unprivileged* UDP socket (no root) and must
**pin its source port** — iDRAC6 binds an authenticated session to the
`(ip, port)` of the Activate Session packet, so every later command
has to leave from the same port. `sr1()`, being stateless and
ephemeral-port, can't carry that. So zipmi slides one rung down on
purpose.

You move between rungs mid-session at will. Build with scapy, drop to
a plain unprivileged socket to do the I/O yourself, then climb back
into scapy to dissect — reusing the `ping` from §2:

```pycon
>>> import socket
>>> s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
>>> s.settimeout(2)
>>> s.connect(("192.168.0.23", 623))
>>> s.send(bytes(ping))                 # ping, not pkt — no IP/UDP at this rung
12
>>> reply = RMCP(s.recv(4096))          # back into scapy to dissect
>>> reply[ASF].msg_type
'PresencePong'
```

Note `bytes(ping)` (12 B), not `bytes(pkt)`: a UDP socket supplies its
own IP/UDP, so you serialize only from RMCP down — and `recv` hands
back exactly that UDP payload, so `RMCP(...)` parses it with nothing to
peel. That asymmetry *is* the rung change: scapy's L3 owned IP/UDP for
you in §2; here you traded that (and the root requirement) for the
kernel's UDP stack and drive the RMCP bytes yourself.

…or skip all of that and let `Transport` own the socket while still
handing you scapy packets in and out:

```pycon
>>> from zipmi.core import Transport
>>> t = Transport(host="192.168.0.23")
>>> msg, resp = t.sessionless_request(0x06, 0x01)   # Get Device ID
>>> resp.summary()
'GetDeviceIDResp'
```

### Wire trace from Python — the `-v` / `-d` flags as attributes

The CLI's `-v` / `-d` aren't magic; they just set two attributes on
the `Transport`. Set them yourself and any rung at or above Transport
narrates itself — no shell, no pcap:

```pycon
>>> t = Transport(host="192.168.0.23")
>>> t.wire_trace = 2          # 0 off · 1 events · 2 events + hex  (== -d)
>>> t.wire_color = True       # ColorBrewer field colouring        (== -n off)
>>> from zipmi.scapy_ipmi.commands import GetChanAuthCapsReq
>>> _ = t.sessionless_request(0x06, 0x38,
...         GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4))
  [13:35:27.256] → send  23B  Get Channel Authentication Capabilities   192.168.0.23:623
          → SEND Get Channel Authentication Capabilities   0600ff07000000000000000000092018c88100388e04b5
  [13:35:27.283] ← recv  30B  (reply)                                  192.168.0.23:623
          ← RECV                                           0600ff0700000000000000000010811c632000380001861403000000000a
```

`wire_trace = 1` drops the hex and keeps just the timestamped event
lines (the `-v` view). For a `Session`, reach the same knob through
`s.transport` — set it **before** the `with` block to also trace the
auth handshake (those lines get a `[setup]` tag), or after it to watch
only your work commands:

```pycon
>>> from zipmi.core import Session
>>> s = Session(host="192.168.0.23", username="root", password="calvin")
>>> s.transport.wire_trace = 1            # trace setup too
>>> with s:
...     d = s.get_device_id()
...
  [13:35:54.448] [setup] → send  38B  Get Session Challenge                     192.168.0.23:623
  [13:35:54.469] [setup] ← recv  42B  (reply)                                  192.168.0.23:623
  [13:35:54.469] [setup] → send  59B  Activate Session                          192.168.0.23:623
  [13:35:54.470] [setup] ← recv  48B  (reply)                                  192.168.0.23:623
  [13:35:54.471] [setup] → send  22B  Set Session Privilege Level               192.168.0.23:623
  [13:35:54.472] [setup] ← recv  23B  (reply)                                  192.168.0.23:623
  [13:35:54.472] → send  21B  Get Device ID                             192.168.0.23:623
  [13:35:54.480] ← recv  37B  (reply)                                  192.168.0.23:623
```

That `[setup]`-tagged block is the entire IPMI 1.5 three-round-trip
handshake (challenge → activate → set-privilege) made visible from
inside Python — the single best way to *see* what §5 below describes.

## 4. Build a real IPMI packet — Get Channel Auth Caps

This one walks the full layer cake: RMCP / IPMI 1.5 Session / IPMB
message / command-specific request payload.

```pycon
>>> from zipmi.scapy_ipmi.ipmi15 import IPMI15_Session, IPMI_Message
>>> from zipmi.scapy_ipmi.commands import GetChanAuthCapsReq

>>> req = GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4)
>>> bytes(req).hex()
'8e04'

>>> ipmb = IPMI_Message(net_fn=0x06, cmd=0x38, data=bytes(req))
>>> bytes(ipmb).hex()
'2018c88100388e04b5'
```

Notice both checksums (`c8`, `b5`) computed automatically — that's
`post_build` doing the IPMB 2's-complement-of-sum work.

```pycon
>>> pkt = RMCP(msg_class=7) / IPMI15_Session() / ipmb
>>> bytes(pkt).hex()
'0600ff07000000000000000000092018c88100388e04b5'
```

23 bytes. Send, sniff, decode:

```pycon
>>> from zipmi.core import Transport
>>> t = Transport(host='192.168.0.23')
>>> _, resp = t.sessionless_request(0x06, 0x38, req)
>>> resp.show()
###[ Get Channel Auth Caps Response ]###
  comp_code = OK
  channel   = 1
  auth_type_support= 0x86
  status    = 0x14
  ext_caps  = 0x3
  oem_iana  = b'\x00\x00\x00'
  oem_aux   = 0
>>> resp.auth_types()
['MD2', 'MD5', 'IPMI2.0']
```

## 5. Open an authenticated 1.5 session

The high-level wrapper:

```pycon
>>> from zipmi.core import Session
>>> with Session(host='192.168.0.23', username='root', password='calvin') as s:
...     d = s.get_device_id()
...     print(f"{d.manufacturer_id_int()}, fw {d.fw_revision()}")
...
674, fw 1.70
```

Under the hood, `Session.activate()` does:

1. `Get Session Challenge` — sessionless, returns a temp session id +
   a 16-byte challenge string.
2. `Activate Session` — first authenticated message. The 16-byte MD5
   AuthCode in the session header is `MD5(pw‖sid‖msg‖seq‖pw)`.
3. `Set Session Privilege Level` — bumps the session to Admin.

The Activate Session AuthCode formula is one of the easier-to-get-wrong
parts of IPMI; we verified ours byte-for-byte against an `ipmitool -A
MD5` capture.

## 6. Step into the bytes

You can crack any session open with the same Scapy mechanics:

```pycon
>>> # Reproduce the IPMB request that get_device_id() sent.
>>> req = IPMI_Message(net_fn=0x06, cmd=0x01)
>>> bytes(req).hex()
'2018c88104013e'
```

The 6 fixed-position bytes (rsAddr, NetFn|LUN, chk1, rqAddr,
seq|LUN, cmd) plus the trailing chk2.

Want to see exactly how a captured session decodes? Run:

```bash
$ tcpdump -nn -w /tmp/zipmi.pcap 'udp port 623' &
$ zipmi mc info
$ kill %1
$ python -c "from scapy.utils import rdpcap; \
             import zipmi; \
             [p.show() for p in rdpcap('/tmp/zipmi.pcap')]"
```

Every packet dissects automatically, all the way down to the named
fields of the command payload class.

## 7. Going lanplus (RMCP+ / RAKP / AES-CBC)

```pycon
>>> with Session(host='192.168.0.23', username='root', password='calvin',
...              lanplus=True, cipher_suite=3) as s:
...     d = s.get_device_id()
...
>>> d.product_id
256
```

Behind that two-line snippet zipmi did:

1. **Open Session Request** (payload type `0x10`) — proposes auth
   alg 1 (HMAC-SHA1), integrity alg 1 (HMAC-SHA1-96), conf alg 1
   (AES-CBC-128). The BMC echoes back its own session id.
2. **RAKP1 → RAKP2** — exchange random nonces and the BMC's GUID,
   verify the BMC's HMAC: `HMAC(K_uid, sid_c‖sid_m‖R_c‖R_m‖GUID‖
   role‖ulen‖uname)`.
3. **RAKP3 → RAKP4** — send our HMAC `HMAC(K_uid, R_m‖sid_c‖role‖
   ulen‖uname)`, verify the BMC's truncated ICV: `HMAC(SIK, R_c‖
   sid_m‖GUID)[:12]` where `SIK = HMAC(K_uid, R_c‖R_m‖role‖ulen‖
   uname)`.
4. Derive `K1 = HMAC(SIK, 0x01*20)` and `K2 = HMAC(SIK, 0x02*20)`.
   K2[:16] is the AES-128 key.
5. Set Session Privilege Level — encrypted with AES-CBC, integrity-
   protected with HMAC-SHA1-96 over the whole session header through
   the next-header byte.
6. (Then the actual `Get Device ID` rides on the same machinery.)

Every one of those HMAC formulas is in
`zipmi/scapy_ipmi/crypto.py` and verified against an oracle pcap from
Dell iDRAC6.

## 8. Send raw bytes — `Session.send_raw()`

Need to test a NetFn/Cmd we haven't modelled? `send_raw` skips the
response-payload registry and gives you the bytes:

```pycon
>>> with Session(host='192.168.0.23', username='root', password='calvin') as s:
...     cc, body = s.send_raw(0x06, 0x01)   # Get Device ID
...     print(f"cc=0x{cc:02x}  body={body.hex()}")
...
cc=0x00  body=20800170 02dfa202 00000100 00150000
```

Or from the shell:

```bash
$ zipmi raw 0x06 0x01
20 80 01 70 02 df a2 02 00 00 01 00 15 00 00
```

Same bytes ipmitool emits for the same request. That's our oracle.

## 9. Fuzzing-friendly building blocks (Phase 6 preview)

Every field we declared is a real Scapy field — no opaque blobs.
Which means you can:

```pycon
>>> from scapy.all import fuzz
>>> fuzzy = fuzz(IPMI_Message(net_fn=0x06, cmd=0x01))
>>> bytes(fuzzy).hex()        # different garbage every time
'b03cad0d c8a1015c'
```

`Session.send_cmd` accepts any `Packet`, so you can hand `fuzz()`
output straight into the wire. The fuzz harness in `zipmi/fuzz/`
(coming Phase 6) is just a wrapper around this one trick plus a
crash detector.

## 10. OEM commands (Phase 5 preview)

OEM commands live OUT of the base namespace. To register Dell's
NetFn 0x30 dispatch table:

```pycon
>>> import zipmi
>>> zipmi.load_vendor("idrac6")   # populates OEM_CMD_NAMES + OEM_PAYLOADS
```

After this, `(0x30, 0xC0)` (Dell PROCHOT throttle) and friends
decode with named payload classes. Without `load_vendor` they go
through the generic `send_raw` path. Keeps a Supermicro pcap from
being decoded with Dell command names by accident.

## 11. The virtual BMC (Phase 5 preview)

You'll be able to spin up a fake BMC for tests and fuzzing:

```bash
$ zipmi vbmc serve --persona dell_idrac6 --port 6230 &
$ zipmi -H 127.0.0.1 -p 6230 -U root -P calvin mc info
```

Useful for:

- CI without a live BMC.
- Fuzz target you can crash on demand (vbmc has injectable wedges).
- Conformance testing the client (does the persona look like a real
  iDRAC6? Does an OS install workflow work?).

## Where to read further

| Topic                          | File                                      |
| ------------------------------ | ----------------------------------------- |
| Phase plan + repo layout       | `docs/architecture.md`                    |
| 1.5 quirks observed            | `docs/ipmi15-notes.md`                    |
| RMCP+ state machine + framing  | `docs/ipmi20-rakp.md`                     |
| Cmd-by-cmd status              | `docs/command-table.md`                   |
| Spec PDFs                      | `/Users/zen/phd/dox/specs/IPMI*.pdf`      |

Happy hacking.
