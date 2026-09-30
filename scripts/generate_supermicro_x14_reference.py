#!/usr/bin/env python3
# z-artifact: b51bf927-5223-4d62-bcd5-aa4fce800f7b
"""Generate the firmware-bound Supermicro X14 OEM reference and table."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.cli.oem_cmds import _vendor_listing
from zipmi.scapy_ipmi.oem.intel import INTEL_COMMANDS
from zipmi.scapy_ipmi.oem.supermicro_x14 import (
    SUPERMICRO_X14,
    X14_CATALOG,
    X14_FIRMWARE_SHA256,
    X14_PRIMARY_PROVIDER_BUILD_ID,
    X14_PRIMARY_PROVIDER_SHA256,
    X14_REGISTRATIONS,
    X14_ROOTFS_SHA256,
)


REFERENCE = ROOT / "docs/supermicro-x14-command-reference.html"
TABLE = ROOT / "docs/supermicro-x14-command-table.html"
REFERENCE_ARTIFACT = "b2990741-fae4-4b93-a523-3cc2940fb614 generated"
TABLE_ARTIFACT = "f5ca7437-fa33-437e-a87e-bc3d1899631b generated"
LIVE_RUN = "20260929T004726Z-90bbc3db-d22b-4660-a34b-e64abb8c8016"


def _length(bounds: tuple[int | None, int | None]) -> str:
    low, high = bounds
    if low == high and low is not None:
        return f"Exactly {low} payload bytes"
    if high is None:
        return f"At least {low or 0} payload bytes"
    return f"{low or 0}–{high} payload bytes"


def _send(vendor: str, key: tuple[int, ...], command: dict) -> str:
    if not command.get("runnable", True):
        return "Host system interface only; no supported LAN route"
    words = ["zipmi", "oem", vendor]
    if command["safety"] != "read-only":
        words.append("--unsafe")
    words.append(shlex.quote(command["name"]))
    low, high = command["request_length"]
    fixed = len(command.get("prefix") or bytes(key[2:]))
    remaining_low = None if low is None else max(0, low - fixed)
    remaining_high = None if high is None else max(0, high - fixed)
    if remaining_low or remaining_high:
        words.append(
            f"<{remaining_low} payload bytes>"
            if remaining_low == remaining_high else "<payload bytes>"
        )
    return " ".join(words)


def _interface(key: tuple[int, ...], delegated: bool) -> str:
    if delegated:
        return "Intel OEM NetFn 0x2e; IANA 0x000157 prefix is auto-supplied"
    if key[0] == 0x2C:
        return f"Group-extension NetFn 0x2c; group 0x{key[2]:02x} is auto-supplied"
    return f"Raw OEM NetFn 0x{key[0]:02x} over authenticated IPMI"


def _live(key: tuple[int, ...], delegated: bool) -> tuple[bool, str]:
    if key[:2] == (0x32, 0x22):
        return True, f"Run {LIVE_RUN}: exact empty read-only handshake reached the RAS backend and returned 0xff"
    if key[:2] == (0x32, 0x23):
        return True, f"Run {LIVE_RUN}: empty request reached RasSetData; state effect is unknown (not safe evidence)"
    if delegated and key[:2] == (0x2E, 0xCA):
        return True, f"Run {LIVE_RUN}: exact IANA-only request reached version lookup and returned 0xff"
    return False, "No exact non-mutating request retained for this operation"


_PARTIAL_REQUESTS = {
    (0x30, 0x68, 0x65), (0x30, 0x68, 0x79), (0x30, 0x68, 0xFC),
    (0x30, 0x51, 0x28), (0x30, 0xA0, 0x04), (0x30, 0xA0, 0x05),
    (0x30, 0xA0, 0x09), (0x30, 0xA0, 0x0A), (0x30, 0xA0, 0x0B),
    (0x30, 0xA0, 0x0C), (0x30, 0xA0, 0x0E), (0x30, 0xA0, 0x32), (0x30, 0xA0, 0x36),
    (0x30, 0x51, 0x28, 0x00), (0x30, 0x51, 0x28, 0x20), (0x30, 0x51, 0x28, 0x21),
}
_PARTIAL_RESPONSES = {
    (0x30, 0x68, 0x4C), (0x30, 0x68, 0x4D), (0x30, 0x68, 0x52),
    (0x30, 0x68, 0x60), (0x30, 0x68, 0x63), (0x30, 0x68, 0x69), (0x30, 0x68, 0x6C),
    (0x30, 0x51, 0x16), (0x30, 0x51, 0x28), (0x30, 0x51, 0xF9),
    (0x30, 0xA0, 0x09), (0x30, 0xA0, 0x0E), (0x30, 0xA0, 0x18),
    (0x30, 0xA0, 0x32), (0x30, 0xA0, 0x36),
    (0x30, 0x51, 0x28, 0x05), (0x30, 0x51, 0x28, 0x08),
    (0x30, 0x51, 0x28, 0x0F), (0x30, 0x51, 0x28, 0x20),
    (0x30, 0x51, 0x28, 0x21), (0x30, 0x51, 0x28, 0x30),
}


def _layout_status(fields: list[dict] | None, bounds: tuple[int | None, int | None], partial: bool = False) -> str:
    if fields is None or bounds == (None, None):
        return "Unknown"
    if bounds[0] is None or bounds[1] is None or partial:
        return "Partial"
    if bounds == (0, 0) and not fields:
        return "Complete"
    generic = any(
        field.get("meaning") == "Recovered typed field"
        or field.get("name", "").startswith(("arg", "response"))
        or field.get("name", "").startswith("field")
        or field.get("type") == "see meaning"
        or field.get("offset") == "var"
        or any(marker in field.get("meaning", "").lower()
               for marker in ("opaque", "remain partial", "unresolved", "unknown"))
        for field in fields
    )
    return "Partial" if generic else "Complete"


def _operation_rows() -> list[dict]:
    rows = []
    catalogs = (
        ("supermicro-x14", "supermicro-x14", SUPERMICRO_X14, False),
        ("openbmc-intel", "intel", INTEL_COMMANDS, True),
    )
    for vendor, listing_vendor, catalog, delegated in catalogs:
        public = _vendor_listing(listing_vendor)
        for key, command in catalog.items():
            live, live_text = _live(key, delegated)
            prefix = command.get("prefix") or bytes(key[2:])
            qualifier = " ".join(f"{byte:02x}" for byte in prefix)
            public_name = public[key]["name"]
            identity = key
            rows.append({
                "id": f"{key[0]:02x}/{key[1]:02x}" + (f" data {qualifier}" if qualifier else ""),
                "name": public_name, "purpose": command["purpose"],
                "send": _send(vendor, key, {**command, "name": public_name}), "safety": command["safety"],
                "safety_note": command.get("safety_note", command["side_effects"]),
                "execution": (
                    "No distinct named route" if not command.get("runnable", True)
                    else "Allowed by default" if command["safety"] == "read-only"
                    else "Requires --unsafe"
                ),
                "request": {
                    "status": _layout_status(command["request_fields"], command["request_length"], identity in _PARTIAL_REQUESTS),
                    "length": _length(command["request_length"]),
                    "summary": command["purpose"], "fields": command["request_fields"],
                },
                "response": {
                    "status": _layout_status(command["response_fields"], command["response_length"], identity in _PARTIAL_RESPONSES),
                    "length": _length(command["response_length"]),
                    "summary": command["purpose"], "fields": command["response_fields"],
                },
                "privilege": command["privilege"], "interface": _interface(key, delegated),
                "availability": command["activation"],
                "completion_codes": command["completion_codes"],
                "live": live, "live_text": live_text,
                "evidence": command["evidence"], "confidence": command["confidence"],
            })
    return rows


def _registration_identity(row: dict) -> tuple:
    netfn, command = int(row["netfn"], 0), int(row["command"], 0)
    if row.get("classification") == "group":
        return netfn, command, int(row["group_id"], 0)
    if row.get("classification") == "oem_iana_0x000157":
        return netfn, command, 0x157
    return netfn, command


def _oem_identities() -> set[tuple]:
    return {
        _registration_identity(row) for row in X14_REGISTRATIONS
        if row.get("classification") in {"raw", "group", "oem", "oem_iana_0x000157"}
    }


def reference_page() -> dict:
    providers = X14_CATALOG["auxiliary"]["firmware"]["providers"]
    provider_hashes = "; ".join(f"{row['name']} {row['sha256']}" for row in providers)
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "Supermicro X14SBSC-RoT OEM IPMI command reference",
        "scope": (
            "Firmware-bound contracts for every Supermicro-private, DMTF/DCMI group, RAS, "
            "and delegated Intel Node Manager operation in BMC firmware 01.01.06.07."
        ),
        "provenance": [
            ("Target", "Supermicro X14SBSC-RoT / E601MS; AST2600 OpenBMC"),
            ("Firmware SHA-256", f"<code>{X14_FIRMWARE_SHA256}</code>"),
            ("Rootfs SHA-256", f"<code>{X14_ROOTFS_SHA256}</code>"),
            ("Primary provider SHA-256", f"<code>{X14_PRIMARY_PROVIDER_SHA256}</code>"),
            ("Primary provider build ID", f"<code>{X14_PRIMARY_PROVIDER_BUILD_ID}</code>"),
            ("Primary analysis artifact", "<code>0272c7fd-d925-59f2-84fe-599de43926eb</code>"),
            ("Prior semantic-input archive", "<code>851806d6-8607-5cfd-807e-a8191ff9e94a</code> (superseded by current catalog)"),
            ("Current contract catalog", "<code>b6b01e08-aa1f-5e20-9541-11fa042e10ad</code>"),
            ("Auxiliary analysis artifact", "<code>503c7d17-fa17-5a55-9e43-bba44155ebd5</code>"),
            ("Live dispatch evidence", "<code>26cdea4a-d4ff-55a8-a9c3-d859ddf77af2</code>; includes one state-effect-unknown RAS set request"),
            ("All provider SHA-256 values", f"<code>{provider_hashes}</code>"),
            ("Registration closure", "116 executed registrations / 115 unique wire identities; one 0x0a/0x48 collision"),
            ("OEM/group closure", "66 identities: 52 primary + three RAS + 11 delegated Intel Node Manager"),
            ("Hidden selector census", "150 primary selectors plus 22 named 0x51/0x28 operations; its 0x00..0x87 range has 20 implemented and 116 rejected values, plus implemented 0xdb and 0xff"),
        ],
        "links": [{"label": "Compact Supermicro X14 command table", "href": "supermicro-x14-command-table.html"}],
        "operations": _operation_rows(),
        "commands": sorted({identity[:2] for identity in _oem_identities()}),
        "gaps": (
            "The five provider registration sets and top-level selector census are closed. The 0x30/0x51 selector 0x28 "
            "has 22 named child routes with recovered operand and length rules; several D-Bus action names and variable "
            "result semantics remain unresolved and are marked Partial. Layouts marked Partial have open byte bounds or unresolved "
            "field/behavior meanings. "
            "Standard Sensor/SDR/Storage/App/Chassis overrides are inventoried in the compact table and use zipmi's "
            "standard command implementations. Group 0x52 commands 0x01/0x02 are system-interface-only and therefore "
            "have no supported LAN route."
        ),
        "live_evidence": (
            f"Authenticated RMCP+ run {LIVE_RUN} reached primary, group, RAS, Intel NM, Sensor, and Storage handlers. "
            "The run included an empty 0x32/0x23 request that reached RasSetData; its effect is unknown and the run "
            "is not wholly non-mutating evidence. Exact read-only RAS Handshake and Intel Get NM Version requests "
            "reached their backends. The guest was then stopped and was not restarted."
        ),
        "sources": [
            '<a href="../zipmi/data/sources/supermicro-x14-contracts.json">Target registration and operation catalog</a>',
            '<a href="../zipmi/scapy_ipmi/oem/supermicro_x14.py">Supermicro X14 routes and codecs</a>',
            '<a href="../zipmi/scapy_ipmi/oem/intel.py">Delegated Intel Node Manager routes and codecs</a>',
            '<a href="evidence/20260929T-supermicro-x14-live-dispatch.json">Live dispatch evidence</a>',
            '<a href="https://www.dmtf.org/sites/default/files/standards/documents/DSP0270_1.3.1.pdf">DMTF DSP0270 1.3.1</a>',
            '<a href="https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/intel-power-node-manager-v3-spec.pdf">Intel Node Manager 3.0 specification</a>',
        ],
    }


def _compact_qualifier(row: dict) -> str:
    if row.get("classification") == "group":
        return f"group {row['group_id']}"
    if row.get("classification") == "oem_iana_0x000157":
        return "IANA 57 01 00"
    return row["classification"].replace("_", " ")


def compact_page() -> dict:
    rows = []
    for registration in X14_REGISTRATIONS:
        netfn, command = int(registration["netfn"], 0), int(registration["command"], 0)
        evidence = registration.get("evidence", "target provider constructor audit")
        if isinstance(evidence, dict):
            evidence = "; ".join(f"{name} {value}" for name, value in evidence.items())
        if (netfn, command, registration["handler"]) == (0x30, 0x51, "OEM51Handler"):
            evidence += (
                "; selector 0x28 child 0x00/A=4 and child 0x01 invoke ProvisionManager.doProvisioning: "
                "one-byte result is 1 when the asynchronous worker starts, 0 when rejected/already active; "
                "state-changing and unsafe-gated; selector 0x20 MMBI methods reach retained mmbibridged "
                "(set ay->n; get n+ay, exactly 8 bytes accepted only on status 0; byte 0 selects the "
                "channel-dependent Blowfish schedule, bytes 1 onward are raw key material, and the validated "
                "GET value is the encrypted repeated BoardId block); checkEncHashData is not called by IPMI"
                "; selector 0x28 child 0x03 reads SecurityManager.readCPLDVersion() as int64 and returns the "
                "low three bytes without status translation; pinned smci-security-mgr opens /dev/spitee and "
                "issues ioctl 0xc0206b0c, and its open/ioctl failure path copies an uninitialized stack word "
                "into those response bytes; helper exceptions have no child-local completion-code mapping"
                "; child 0x09 is an unrestricted generic readCpldReg register query; shipped scripts establish "
                "register 0x00 bit 4 MSMI latching, 0x01 bit 2 temporary surprise reset, 0x08 bits 6/7 BMC "
                "reset/factory-default flags, 0x0a value 0x03 for the BoardId-7504 extended fan-delay workaround, "
                "and a boot-time zero write to 0x0b; a separate /dev/spi1nand0 write of 0x13 to offset 0x18 "
                "documents bits 4/0 as BMC boot OK/exit U-Boot but is not proven to share the D-Bus backend"
                "; its matching-daemon low-level reader opens /dev/spitee and issues ioctl 0xc0046b01 with the "
                "register index in bits 16..23; success returns the low byte and open/ioctl failure is -5. The provider "
                "directly calls smci::core::get_rot_cpld_reg; the daemon reader is identified by type and ioctl behavior"
                "; child 0xdb reads /usr/share/log/3068db.log only for operand a=5, returning exactly 256 bytes "
                "(truncating longer content and zero-padding shorter, missing, or unreadable content; operand b ignored)"
                "; child 0x0f operand B is a device selector passed to dumpDboot(B, 0): 0 selects "
                "Backplane_0_CPLD_0, 3 selects AOMboard_1_CPLD_1, 5 selects MidplaneSBB_CPLD_1, and 9 selects "
                "Fanboard_1_CPLD_1; other selectors fail. The matching smci-cpld-update-mgr-svc names "
                "and overwrites /tmp/cpld_flash_dump.bin with three 64-KiB blocks (0x30000 bytes on success); "
                "hardware/read/write failures may leave a partial file; uncaught D-Bus exceptions map to 0xff"
                "; selector 0x39 OEMAddDelUser: operation 1 carries slot 1..15, declared username/password lengths, "
                "and Base64 credentials split at the first ASCII 'G' (0x47); it creates the user only in an empty "
                "slot, sets user ID slot+1, enables the account, and emits MEL 0x15. Operation 2 takes exactly "
                "one slot byte, deletes that user via xyz.openbmc_project.User.Manager / "
                "xyz.openbmc_project.Object.Delete.Delete, and emits MEL 0x16; both succeed with no response payload"
                "; selector 0x13 OEMGetSetBBP is only a lockdown-gated validator: its parameter/value bytes are "
                "range-checked opaque compatibility fields and never access BBP state"
            )
        if (netfn, command, registration["handler"]) == (0x30, 0x68, "OEM68Handler"):
            evidence += (
                "; selector 0x63 OEMSetGetLinkConf operation 2 returns fixed mask 0x59; the Supermicro "
                "X14/H14 callsite and mode ordinals map bit 0 to auto negotiation, bit 3 to 100M "
                "half-duplex, bit 4 to 100M full-duplex, and bit 6 to 1G full-duplex"
                "; selector 0xfc ClearConfigOption masks 0x00000004 and 0x02000000 call anonymous helper "
                "0x984cc: it scans /usr/share/log, byte-prefix matches entry filenames against ASCII `mel`, "
                "removes each match and /usr/share/log/rsyslog_server if present, then requests systemd "
                "Manager.ReloadUnit(rsyslog.service, replace); only 0x00000004 emits MEL 0x7b; selector 0x79 "
                "OEMGetPSUInfo routes raw command/length bytes to the "
                "pinned com.SMCI.PWS GetPSURaw callback; it issues ioctl 0x707 on /dev/i2c-%d, "
                "returns a D-Bus byte array, and retries up to 4 ioctl attempts then 10 helper calls "
                "with 100 ms sleeps before throwing std::logic_error ('Can't get PSURaw Data after retries.'). "
                "Uncaught std::logic_error or SdBusError reaches the pinned typed-handler wrapper "
                "and returns completion code 0xff with no payload"
            )
        if (netfn, command, registration["handler"]) == (0x30, 0xa0, "OOBHandler"):
            evidence += (
                "; selector 0x36 LicenseFileAction operation 1 unlinks the selected license file, then emits "
                "MEL EventId 5 (deactivated): slot 1 is SFT-OOB-LIC and slot 2 is SFT-DCMS-SINGLE on KCS "
                "and RMCP; operation 0 returns 0x04 for SFT-DCMS-SINGLE (license file 2), otherwise 0x01 "
                "for SFT-OOB-LIC (license file 1), otherwise zero"
            )
        rows.append({
            "address": f"0x{netfn:02x} / 0x{command:02x}",
            "qualifier": _compact_qualifier(registration),
            "handler": registration["handler"],
            "privilege": registration.get("privilege_name", registration.get("privilege", "—")),
            "request": "See detailed operation or standard IPMI contract",
            "activation": registration["activation"],
            "evidence": f"{registration['provider']}: {evidence}",
        })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "Supermicro X14SBSC-RoT compact IPMI provider table",
        "scope": "One row per executed registration across the five target provider ELFs.",
        "provenance": [
            ("Firmware SHA-256", f"<code>{X14_FIRMWARE_SHA256}</code>"),
            ("Rootfs SHA-256", f"<code>{X14_ROOTFS_SHA256}</code>"),
            ("Primary provider SHA-256", f"<code>{X14_PRIMARY_PROVIDER_SHA256}</code>"),
            ("Known collision", "Storage 0x0a/0x48 is registered by two providers"),
        ],
        "metrics": [
            (116, "Executed registration rows"), (115, "Unique wire identities"),
            (66, "OEM/group identities"), (150, "Hidden primary selector operations"),
        ],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/supermicro-x14-contracts.json", "label": "Closed target catalog"},
            {"href": "supermicro-x14-command-reference.html", "label": "Detailed operation reference"},
            {"href": "evidence/20260929T-supermicro-x14-live-dispatch.json", "label": "Live dispatch evidence (one probe may have changed state)"},
        ],
    }


def emit(path: Path, document: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == document
    path.write_text(document)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = (
        (REFERENCE, render_reference(reference_page())),
        (TABLE, render_command_table(compact_page())),
    )
    valid = all(emit(path, document, args.check) for path, document in documents)
    if args.check and not valid:
        print("Supermicro X14 generated documentation is stale", file=sys.stderr)
        return 1
    if not args.check:
        for path, _document in documents:
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
