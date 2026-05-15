"""Generic spec-compliant baseline persona for the virtual BMC."""

from __future__ import annotations

from ..state import Persona, default_sel_entries


def build() -> Persona:
    p = Persona(
        name="generic",
        manufacturer_id=0,
        product_id=0x0001,
        sel_entries=default_sel_entries(),
    )
    # Pad user_name to 16 bytes per IPMI 1.5 §22.16 / §22.17.
    p.user_name = b"root".ljust(16, b"\x00")
    return p
