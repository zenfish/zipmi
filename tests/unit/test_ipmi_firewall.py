"""Pure-decode tests for scripts/ipmi_firewall.py (no BMC needed)."""
import importlib.util, pathlib
_spec = importlib.util.spec_from_file_location(
    "ipmi_firewall", pathlib.Path(__file__).parents[2] / "scripts" / "ipmi_firewall.py")
fw = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(fw)


def test_bits_lsb_first():
    # byte0=0x01 -> cmd0; byte1=0xc0 -> cmds 14,15 (bits 6,7 of byte1)
    assert fw._bits(bytes([0x01, 0xc0])) == [0, 14, 15]
    assert fw._bits(bytes([0x00, 0x00])) == []


class _FakeSess:
    """Replays the real Get NetFn Support response captured from the Cray XD670."""
    def send_raw(self, netfn, cmd, data=b""):
        if (netfn, cmd) == (0x06, 0x09):   # Get NetFn Support, channel 0x0e
            return 0, bytes.fromhex("026f004083000000000000000000000000")
        return 0xc1, b""


def test_netfn_support_decode_matches_cray():
    # reserved byte0 skipped; pairs -> even NetFns. 0x6f 0x00 0x40 0x83 ...
    got = fw.get_netfn_support(_FakeSess(), 0x0e)
    assert got == [0x00, 0x02, 0x04, 0x06, 0x0a, 0x0c, 0x2c, 0x30, 0x32, 0x3e]
