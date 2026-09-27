#!/usr/bin/env python3
# z-artifact: 4da799c5-b238-478e-9993-df79dba4fdb5
"""Generate compact firmware-identity tables for documented OEM targets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from oem_command_table import render_command_table


ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "zipmi/data/sources"
OUTPUTS = {
    "advantech": ROOT / "docs/advantech-asmb787-command-table.html",
    "lenovo": ROOT / "docs/lenovo-xcc-command-table.html",
    "fujitsu": ROOT / "docs/fujitsu-irmc-s6-command-table.html",
}
PRIVILEGE = {
    0: "None / pre-session", 1: "Callback", 2: "User", 3: "Operator",
    4: "Administrator", 5: "OEM",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hex_bytes(values: list[int]) -> str:
    return " ".join(f"0x{value:02x}" for value in values) or "—"


def advantech_page() -> dict:
    source = SOURCES / "advantech-asmb787-oem-dispatch.csv"
    with source.open(newline="") as stream:
        records = list(csv.DictReader(stream))
    assert len(records) == 187
    identities = {(row["netfn"], row["cmd"]) for row in records}
    assert len(identities) == 187
    rows = []
    for row in records:
        evidence = (
            f'{row["module"]}; table {row["table"]}; entry {row["entry_address"]}; '
            f'{row["entry_evidence"]}; module SHA-256 {row["module_sha256"]}'
        )
        rows.append({
            "address": f'{row["netfn"]} / {row["cmd"]}',
            "qualifier": row["selector"] or "—",
            "handler": row["handler"],
            "privilege": row["privilege"],
            "request": row["request_length_semantics"],
            "activation": row["activation_status"],
            "evidence": evidence,
        })
    return {
        "artifact_marker": "b1784d1b-6fa1-40aa-b972-42363b60497a generated",
        "title": "Advantech ASMB-787 compact firmware command table",
        "scope": ("Corrected top-level IPMI dispatch identities recovered from the ASMB-787 "
                  "firmware. Selector-level behavior belongs in the linked command reference."),
        "provenance": [
            ("Target", "Advantech ASMB-787 / AMI MegaRAC SP-X 4.0"),
            ("Canonical table SHA-256", f"<code>{digest(source)}</code>"),
            ("Denominator", "187 unique NetFn/Cmd firmware dispatch addresses"),
        ],
        "metrics": [(187, "Registration rows"), (187, "Unique NetFn/Cmd identities"),
                    (len({row["module"] for row in records}), "Owning modules")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/advantech-asmb787-oem-dispatch.csv",
             "label": "Canonical corrected dispatch CSV"},
            {"href": "advantech-asmb787-command-reference.html",
             "label": "Operation-level command reference"},
        ],
    }


def lenovo_request(rules: list[dict]) -> str:
    if not rules:
        return "No dispatcher length rule recovered"
    return "; ".join(
        f'{rule["length_kind"]} {rule["request_length"]} payload bytes'
        for rule in rules
    )


def lenovo_page() -> dict:
    source = SOURCES / "lenovo-xcc-commands.json"
    document = json.loads(source.read_text())
    records = document["commands"]
    assert len(records) == 225
    identities = {(row["netfn"], row["cmd"]) for row in records}
    assert len(identities) == 210
    rows = []
    for row in records:
        registrations = "; ".join(
            f'{item["module"]}:{item["owner"]}' for item in row["registrations"]
        ) or "No registration owner recorded"
        evidence = (f'{row["source"]}; {registrations}; evidence {row["evidenceState"]}; '
                    f'confidence {row["confidence"]}')
        rows.append({
            "address": f'0x{row["netfn"]:02x} / 0x{row["cmd"]:02x}',
            "qualifier": hex_bytes(row["prefix"]),
            "handler": row["handler"],
            "privilege": PRIVILEGE.get(row["privilege"],
                                       "Not recovered" if row["privilege"] is None
                                       else f'Firmware value {row["privilege"]}'),
            "request": lenovo_request(row["requestLengthRules"]),
            "activation": f'{row["dispatch"]}; runnable={str(row["runnable"]).lower()}',
            "evidence": evidence,
        })
    return {
        "artifact_marker": "ed7f4d4d-4072-46ae-a940-d8e423bd43da generated",
        "title": "Lenovo XCC compact firmware command table",
        "scope": ("Firmware registration identities for Lenovo XCC 6.92. Prefix-qualified "
                  "duplicates remain separate; decoded selector operations belong in the reference."),
        "provenance": [
            ("Target", document["firmware"]),
            ("IPMI library SHA-256", "<code>b72294cd8a10699e2cd3827dd1b4aa0a13943c483332af0ceae8ba603cf17485</code>"),
            ("Canonical catalog SHA-256", f"<code>{digest(source)}</code>"),
            ("Denominator", "225 registrations across 210 NetFn/Cmd identities"),
        ],
        "metrics": [(225, "Registration rows"), (210, "Unique NetFn/Cmd identities"),
                    (sum(bool(row["prefix"]) for row in records), "Prefix-qualified rows")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/lenovo-xcc-commands.json",
             "label": "Canonical firmware identity catalog"},
            {"href": "lenovo-xcc-command-reference.html",
             "label": "Operation-level command reference"},
        ],
    }


def fujitsu_page() -> dict:
    source = SOURCES / "fujitsu-irmc-s6-command-tables.tsv"
    operations = json.loads((SOURCES / "fujitsu-irmc-s6-operations.json").read_text())
    with source.open(newline="") as stream:
        records = [
            row for row in csv.DictReader(stream, delimiter="\t")
            if row["table"] and not row["table"].startswith("#") and row["handler"] != "?"
        ]
    assert len(records) == 148
    identities = {
        (int(row["netfn"], 0), int(row["cmd"], 0),
         3 if row["scope"] == "wire LUN 3" else 0)
        for row in records
    }
    assert len(identities) == 138
    rows = []
    for row in records:
        lun = 3 if row["scope"] == "wire LUN 3" else 0
        request = ("Variable payload length" if row["req_len"] == "variable"
                   else f'Exactly {row["req_len"]} payload bytes')
        evidence = (f'table {row["table"]}, index {row["index"]}; ELF record '
                    f'{row["elf_record"]}; Ghidra record {row["ghidra_record"]}; '
                    f'handler address {row["ghidra_handler"]}')
        privilege = int(row["min_priv"], 0)
        rows.append({
            "address": f'{int(row["netfn"], 0):#04x} / {int(row["cmd"], 0):#04x}',
            "qualifier": f"LUN {lun}",
            "handler": row["handler"],
            "privilege": PRIVILEGE.get(privilege, f'Firmware value {privilege:#x}'),
            "request": request,
            "activation": row["scope"],
            "evidence": evidence,
        })
    return {
        "artifact_marker": "5841e0c6-5d19-4340-9a54-7ead12a5f9df generated",
        "title": "Fujitsu iRMC S6 compact firmware command table",
        "scope": ("Registration records recovered from the pinned iRMC S6 IPMI dispatcher. "
                  "LUN-specific and duplicate handler registrations remain separate."),
        "provenance": [
            ("Target", operations["target"]),
            ("IPMI library SHA-256", f'<code>{operations["librarySha256"]}</code>'),
            ("Canonical table SHA-256", f'<code>{digest(source)}</code>'),
            ("Denominator", "148 registrations across 138 NetFn/Cmd/LUN identities"),
        ],
        "metrics": [(148, "Registration rows"), (138, "Unique NetFn/Cmd/LUN identities"),
                    (sum(row["scope"] == "wire LUN 3" for row in records), "LUN 3 rows")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/fujitsu-irmc-s6-command-tables.tsv",
             "label": "Canonical recovered registration table"},
            {"href": "fujitsu-irmc-s6-command-reference.html",
             "label": "Operation-level command reference"},
        ],
    }


def emit(path: Path, text: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == text
    path.write_text(text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    pages = {
        "advantech": advantech_page(),
        "lenovo": lenovo_page(),
        "fujitsu": fujitsu_page(),
    }
    valid = all(
        emit(OUTPUTS[name], render_command_table(page), args.check)
        for name, page in pages.items()
    )
    if args.check and not valid:
        print("OEM command tables are stale")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
