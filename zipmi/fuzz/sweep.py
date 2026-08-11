"""
zipmi.fuzz.sweep — NetFn × Cmd × params sweep with crash detection.

WHAT     Walks every (NetFn, cmd) pair (or a subset) against a target BMC
         (real or vbmc), recording the completion code and response body
         length. Optionally fuzzes the request data field of any cmd
         that accepts data.

WHY      Same pattern we used to enumerate SMI handlers (smi-enumerate
         tool); turns "what does this BMC support" from documentation
         into a measured fact. Catches:
           * commands that wedge the session (crash detection)
           * commands that return unusual cc / unusual length
           * OEM commands missing from spec tables

USAGE    from a Session that's already activated:

             from zipmi.fuzz.sweep import sweep_netfn
             with Session(...) as s:
                 results = sweep_netfn(s, netfn=0x06, rate_hz=10)

         CLI:
             zipmi fuzz sweep --netfn 0x06 --rate 10

OUTPUTS  list[SweepResult] — one per (netfn, cmd) probed. Includes
         exception text on crash so you don't lose context.

RELATED  zipmi/core.py (Session.send_raw), zipmi/vbmc/server.py (target)
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..consts import COMP_CODE
from ..core import IPMIError, Session


# Boundary request-data payloads for data-fuzz: empty, single bytes, full and
# incrementing 16-byte blocks, and an over-long run. Deliberately small so a
# sweep stays fast and doesn't hammer the BMC into a DoS.
BOUNDARY_DATA: tuple[bytes, ...] = (
    b"",
    b"\x00",
    b"\xff",
    b"\x00" * 16,
    b"\xff" * 16,
    bytes(range(16)),
    b"\xff" * 64,
)


@dataclass
class SweepResult:
    netfn: int
    cmd: int
    cc: int | None = None
    body: bytes = b""
    error: str = ""
    elapsed_ms: float = 0.0
    req_data: bytes = b""      # request payload actually sent (data-fuzz)

    @property
    def bmc_responded(self) -> bool:
        """True iff the BMC accepted the cmd (cc != 0xC1 InvalidCommand)."""
        return self.cc is not None and self.cc != 0xC1

    @property
    def bucket(self) -> str:
        """Categorize from the BMC's perspective. See sweep_netfn docstring."""
        if self.error == "skipped":
            return "skipped"
        if self.error:
            return "transport_or_parse_error"
        if self.bmc_responded:
            return "bmc_responded"
        return "bmc_rejected_invalid_cmd"

    @property
    def cc_name(self) -> str:
        if self.cc is None:
            return "—"
        return COMP_CODE.get(self.cc, f"0x{self.cc:02x}")


def sweep_netfn(
    session: Session,
    netfn: int,
    cmds: range | list[int] | None = None,
    rate_hz: float = 10.0,
    skip: set[tuple[int, int]] | None = None,
    on_result: Callable[[SweepResult], None] | None = None,
    data_variants: list[bytes] | tuple[bytes, ...] | None = None,
) -> list[SweepResult]:
    """Iterate cmd 0x00..0xFF for one NetFn; rate-limit with rate_hz.

    `skip` defaults to a small known-dangerous set (Cold/Warm Reset,
    Chassis Power, Close Session) that we don't want fired during a
    casual sweep. Pass `skip=set()` to override.

    `on_result` is invoked synchronously after every probe completes
    (including skipped entries). The callback is the only way to get
    streaming output — without it the caller waits until the full sweep
    finishes before any result is visible.
    """
    if cmds is None:
        cmds = range(0x00, 0x100)
    if skip is None:
        skip = {
            (0x06, 0x02),     # Cold Reset — kicks the BMC
            (0x06, 0x03),     # Warm Reset
            (0x06, 0x3C),     # Close Session — we'd lose our session
            (0x00, 0x02),     # Chassis Power Control — affects host
            (0x00, 0x04),     # Chassis Identify — visible side effect
            (0x0A, 0x47),     # Clear SEL — destructive
        }
    # Default = a single empty payload (pure surface enumeration). Passing
    # data_variants (e.g. BOUNDARY_DATA) turns it into a real request-data fuzz:
    # each cmd is probed once per payload.
    variants = list(data_variants) if data_variants else [b""]
    period = 1.0 / rate_hz if rate_hz else 0.0
    out: list[SweepResult] = []
    wedged = False
    for cmd in cmds:
        if (netfn, cmd) in skip:
            r = SweepResult(netfn, cmd, cc=None, error="skipped")
            out.append(r)
            if on_result:
                on_result(r)
            continue
        for data in variants:
            t0 = time.perf_counter()
            result = SweepResult(netfn=netfn, cmd=cmd, req_data=bytes(data))
            try:
                cc, body = session.send_raw(netfn, cmd, data)
                result.cc = cc
                result.body = body
            except IPMIError as e:
                result.error = f"ipmi:{e}"
            except (OSError, TimeoutError) as e:
                result.error = f"transport:{e}"
                # Transport error means session may be wedged — bail out.
                result.elapsed_ms = (time.perf_counter() - t0) * 1000
                out.append(result)
                if on_result:
                    on_result(result)
                wedged = True
                break
            except Exception as e:
                result.error = f"crash:{type(e).__name__}:{e}"
            result.elapsed_ms = (time.perf_counter() - t0) * 1000
            out.append(result)
            if on_result:
                on_result(result)
            if period:
                time.sleep(period)
        if wedged:
            break
    return out


# Bucket keys in the order shown to users. Names spell out which side
# is responsible — "BMC" prefix means "the BMC told us this", "transport"
# means our local stack saw an exception.
SUMMARY_BUCKETS = (
    "bmc_responded",            # cc != 0xC1; the BMC accepted the cmd
    "bmc_rejected_invalid_cmd", # cc == 0xC1 InvalidCommand
    "transport_or_parse_error", # OSError, TimeoutError, parser crash
    "skipped",                  # destructive denylist
)


def summarize(results: list[SweepResult]) -> dict[str, list[SweepResult]]:
    """Bucket sweep results by `SweepResult.bucket`."""
    summary: dict[str, list[SweepResult]] = {k: [] for k in SUMMARY_BUCKETS}
    for r in results:
        summary[r.bucket].append(r)
    return summary
