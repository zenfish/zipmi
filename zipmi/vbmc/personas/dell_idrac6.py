"""Dell PowerEdge / iDRAC6 persona for the virtual BMC.

Mimics the fingerprint of a Dell iDRAC6 well enough that ipmitool / zipmi
can't tell a vbmc instance from the real thing on the read-side commands
we model.

Reference: live measurements vs Dell PowerEdge T710 / iDRAC6 1.70.
"""

from __future__ import annotations

from ..state import Persona, default_sel_entries


def build() -> Persona:
    p = Persona(
        name="dell_idrac6",
        manufacturer_id=674,             # Dell
        product_id=0x0100,
        device_id=0x20,
        fw_revision_1=0x01,              # 1.x
        fw_revision_2=0x70,              # x.70
        ipmi_version=0x02,               # 2.0
        sel_entries=default_sel_entries(),
        # Specific GUID seen on lab unit (DELLX...)
        device_guid=bytes.fromhex("44454c4c580010548033b5c04f475131"),
        system_guid=bytes.fromhex("44454c4c580010548033b5c04f475131"),
    )
    p.user_name = b"root".ljust(16, b"\x00")
    p.password  = b"calvin"
    return p
