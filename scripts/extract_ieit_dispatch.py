#!/usr/bin/env python3
# z-artifact: fc154ba8-9e69-4a9f-9728-e23456e8c223
"""Extract the pinned IEIT NF5468M6 OEM dispatch denominator from ELF tables.

Requires pyelftools and an extracted BMC 7.26.05 ``usr/local/lib`` tree.  The
output deliberately contains registration rows, not inferred selector leaves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


FIRMWARE_SHA256 = "b7915aa4be2661d47d78cca6265dc11d8d06c23cc199e0ff80a2adc3ccd7c7d1"
OUTPUT_ARTIFACT_UUID = "d9802625-d126-48cb-b13e-8e6290ac8e75"
EXPECTED_ROWS = 324
EXPECTED_ADDRESSES = 323
PRIVILEGES = {0x02: "User", 0x03: "Operator", 0x04: "Administrator", 0x81: "System"}
VERSIONED_SO = re.compile(r"\.so\.\d+\.\d+\.\d+$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ElfTables:
    def __init__(self, path: Path):
        self.path = path
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        dynsym = self.elf.get_section_by_name(".dynsym")
        if dynsym is None:
            raise ValueError(f"{path}: missing .dynsym")
        self.symbols = list(dynsym.iter_symbols())
        self.by_name = {symbol.name: symbol for symbol in self.symbols}
        self.relocations: dict[int, str] = {}
        for section in self.elf.iter_sections():
            if section.header.sh_type not in {"SHT_REL", "SHT_RELA"}:
                continue
            for relocation in section.iter_relocations():
                symbol = self.symbols[relocation["r_info_sym"]]
                self.relocations[relocation["r_offset"]] = symbol.name

    def close(self) -> None:
        self.stream.close()

    def table_names(self) -> list[str]:
        return [
            symbol.name for symbol in self.symbols
            if symbol["st_info"]["type"] == "STT_OBJECT"
            and "CmdHndlr" in symbol.name
            and "Select" not in symbol.name
        ]

    def _read_symbol(self, name: str) -> tuple[object, bytes]:
        symbol = self.by_name[name]
        address = symbol["st_value"]
        segment = next(
            segment for segment in self.elf.iter_segments()
            if segment["p_type"] == "PT_LOAD"
            and segment["p_vaddr"] <= address < segment["p_vaddr"] + segment["p_filesz"]
        )
        self.stream.seek(segment["p_offset"] + address - segment["p_vaddr"])
        return symbol, self.stream.read(symbol["st_size"])

    def rows(self, table: str, netfn: int, provider: str) -> list[dict]:
        symbol, data = self._read_symbol(table)
        if len(data) % 16:
            raise ValueError(f"{self.path}:{table}: table size is not a multiple of 16")
        rows = []
        for index in range(0, len(data), 16):
            handler = self.relocations.get(symbol["st_value"] + index + 4)
            if not handler:
                continue
            flags1 = int.from_bytes(data[index + 8:index + 12], "little")
            flags2 = int.from_bytes(data[index + 12:index + 16], "little")
            declared_length = flags1 & 0xFF
            rows.append({
                "netfn": netfn,
                "cmd": data[index],
                "privilege_byte": data[index + 1],
                "privilege": PRIVILEGES.get(data[index + 1], f"0x{data[index + 1]:02x}"),
                "handler": handler,
                "handler_address": (
                    f"0x{self.by_name[handler]['st_value']:x}"
                    if handler in self.by_name else None
                ),
                "declared_request_length": None if declared_length == 0xFF else declared_length,
                "flags1": f"0x{flags1:08x}",
                "flags2": f"0x{flags2:08x}",
                "provider": provider,
                "binary": self.path.name,
                "binary_sha256": sha256(self.path),
                "table": table,
                "table_index": index // 16,
            })
        return rows


def find_library(root: Path, name: str) -> Path:
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    if not matches:
        raise FileNotFoundError(f"missing {name} below {root}")
    hashes = {sha256(path) for path in matches}
    if len(hashes) != 1:
        raise ValueError(f"multiple non-identical {name} files below {root}")
    return matches[0]


def extract(root: Path) -> dict:
    rows: list[dict] = []

    core_path = find_library(root, "libipmimsghndlr.so.6.97.0")
    core = ElfTables(core_path)
    rows.extend(core.rows("g_AMI_CmdHndlr", 0x32, "ami-core"))
    core.close()

    plugins: dict[str, Path] = {}
    for path in root.rglob("libipmiamioem*.so.*"):
        if path.is_file() and VERSIONED_SO.search(path.name):
            plugins.setdefault(path.name, path)
    if len(plugins) != 39:
        raise ValueError(f"expected 39 AMI plugin binaries, found {len(plugins)}")
    for name, path in sorted(plugins.items()):
        elf = ElfTables(path)
        tables = []
        for table in elf.table_names():
            candidate = elf.rows(table, 0x32, f"ami-plugin:{name}")
            if candidate:
                tables.append((table, candidate))
        if len(tables) != 1:
            raise ValueError(f"{name}: expected one primary handler table, found {len(tables)}")
        rows.extend(tables[0][1])
        elf.close()

    pdk_path = find_library(root, "libipmipdkcmds.so.6.1.0")
    pdk = ElfTables(pdk_path)
    for table, netfn in (
        ("g_Oem_Chassis_CmdHndlr", 0x00),
        ("g_Oem_NetFn30_CmdHndlr", 0x30),
        ("g_Commer_MixCmdHndlr", 0x34),
        ("g_BiosSetUp_CmdHndlr", 0x38),
        ("g_Commer_CmdHndlr", 0x3C),
        ("g_Intel_CmdHndlr", 0x3E),
    ):
        rows.extend(pdk.rows(table, netfn, "ieit-pdk"))
    pdk.close()

    pnm_path = find_library(root, "libipminmsupport.so.6.6.0")
    pnm = ElfTables(pnm_path)
    rows.extend(pnm.rows("g_PNM_CmdHndlr", 0x30, "intel-pnm"))
    pnm.close()

    hpm_path = find_library(root, "libipmihpm.so.6.22.10")
    hpm = ElfTables(hpm_path)
    rows.extend(hpm.rows("g_HighPayload_CmdHndlr", 0x3E, "ami-hpm-oem"))
    hpm.close()

    rows.sort(key=lambda row: (
        row["netfn"], row["cmd"], row["provider"], row["binary"], row["table_index"]
    ))
    addresses = {(row["netfn"], row["cmd"]) for row in rows}
    if len(rows) != EXPECTED_ROWS or len(addresses) != EXPECTED_ADDRESSES:
        raise ValueError(
            f"denominator drift: {len(rows)} rows / {len(addresses)} addresses; "
            f"expected {EXPECTED_ROWS} / {EXPECTED_ADDRESSES}"
        )
    collisions = {}
    for netfn, cmd in sorted(addresses):
        matches = [row for row in rows if (row["netfn"], row["cmd"]) == (netfn, cmd)]
        if len(matches) > 1:
            collisions[f"0x{netfn:02x}/0x{cmd:02x}"] = [row["handler"] for row in matches]
    return {
        "artifact_uuid": OUTPUT_ARTIFACT_UUID,
        "schema": "zipmi.ieit.dispatch.v1",
        "target": "IEIT NF5468M6 BMC 7.26.05",
        "firmware_sha256": FIRMWARE_SHA256,
        "registration_rows": len(rows),
        "unique_addresses": len(addresses),
        "collisions": collisions,
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library_root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = json.dumps(extract(args.library_root), indent=2) + "\n"
    if args.check:
        if args.output is None:
            parser.error("--check requires --output")
        return 0 if args.output.exists() and args.output.read_text() == document else 1
    if args.output:
        args.output.write_text(document)
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
