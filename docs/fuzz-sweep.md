# `zipmi fuzz sweep` — NetFn × Cmd surface enumeration

Walks cmd `0x00..0xFF` for one NetFn against a target BMC (real or vbmc),
records each completion code, and buckets the result from the **BMC's**
perspective. Empty data field — for parser-strict cmds this still reaches
the handler and returns `0xC7 Request data length invalid`, which is a
"BMC accepted the dispatch" signal rather than a rejection.

## Verbosity

| Flag         | Output style                                                    |
|--------------|-----------------------------------------------------------------|
| (none)       | Summary only at end. No per-row output.                         |
| `-v` / `--verbose` | **Streaming.** Each result printed as it lands. Shows BMC-responded rows + skipped rows. Hides 0xC1 noise (the dominant bucket). |
| `-d` / `--debug`   | **Streaming.** Shows everything including `0xC1 Invalid command` rejects. Useful when you want to see "the BMC saw all 256 dispatches" or to confirm specific cmds are absent. |

Streaming output flushes per row — you see results in real time, not at
the end of the sweep. Cadence is set by `--rate` (default 10 Hz, max
useful ~80 Hz against real iDRAC6 before timeouts dominate).

## Bucket semantics

| Bucket key (in `summary` dict)   | Display label              | What it means                                              |
|----------------------------------|----------------------------|------------------------------------------------------------|
| `bmc_responded`                  | `BMC responded`            | The BMC returned **any** completion code other than `0xC1`. Includes `0x00 Success`, `0xC7 Request data length invalid`, `0xCC Invalid data field`, etc. The dispatch table has a registered handler for this `(NetFn, cmd)`. |
| `bmc_rejected_invalid_cmd`       | `BMC rejected (0xC1)`      | The BMC returned `0xC1 Invalid command` — there is no handler for this `(NetFn, cmd)` on this firmware. |
| `transport_or_parse_error`       | `transport/parse errors`   | Local stack saw an exception: socket timeout, OS error, scapy parse crash, or unhandled Python exception. Not the BMC's fault. |
| `skipped`                        | `skipped (destructive)`    | Hit the destructive-cmd denylist (Cold/Warm Reset, Close Session, Chassis Power, Chassis Identify, Clear SEL). Did not send. |

The bucket name spells out **which side** is responsible. `BMC responded`
is unambiguous: the BMC chose to answer. `transport/parse errors` is
unambiguous: our local stack failed before the BMC's response landed.
This avoids the older ambiguous labels `implemented` (whose perspective?)
and `unsupported` (by zipmi or by the BMC?).

## Completion code labels

The label printed in the `completion code` column comes from
`zipmi.consts.COMP_CODE`, which uses pyghmi-style descriptive strings
(e.g. `Request data length invalid` rather than the older terse
`RequestDataLengthInvalid`). Unknown codes render as `0xNN`.

## Skip list

Default destructive denylist (overridable via `sweep_netfn(skip=...)`):

```
(0x06, 0x02)  Cold Reset           — kicks the BMC, would lose session
(0x06, 0x03)  Warm Reset           — same
(0x06, 0x3C)  Close Session        — would lose our own session
(0x00, 0x02)  Chassis Power        — affects host
(0x00, 0x04)  Chassis Identify     — visible side effect (LED)
(0x0A, 0x47)  Clear SEL            — destructive
```

Skipped entries appear in `-v` / `-d` output marked `[skipped]` so the
operator can see they weren't probed.

## Example

```
$ zipmi fuzz sweep --netfn 0x06 -v
sweep NetFn 0x06 on 192.168.0.23: (streaming)
   Cmd    CC  len  completion code                                          name
  0x01  0x00   15  Success                                                  GetDeviceID
  0x02    --    -  [skipped]                                                _BareCC
  0x03    --    -  [skipped]                                                _BareCC
  0x04  0x00    2  Success                                                  GetSelfTestResults
  0x05  0xc7    0  Request data length invalid                              —
  ...

sweep NetFn 0x06 on 192.168.0.23:
  BMC responded            : 51
  BMC rejected (0xC1)      : 202
  transport/parse errors   : 0
  skipped (destructive)    : 3
```

The `name` column is filled when zipmi has a registered name for the
`(NetFn, cmd)` pair — standard IPMI cmds always; OEM cmds only after
`load_vendor("dell")` / `load_vendor("idrac9")` etc. The CLI auto-loads
the Dell vendor module when sweeping NetFn `0x30` or `0x2E`.
