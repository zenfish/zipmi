#!/usr/bin/env python3
# z-artifact: 258a33ac-2c5a-452d-9faf-30c404136d3a
"""Generate the firmware-bound NVIDIA GB200 OEM reference and command table."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.scapy_ipmi.oem.nvidia import (
    NVIDIA_COMMANDS,
    NVIDIA_GB200_IMAGE_SHA256,
    NVIDIA_PROVIDER_BUILD_ID,
    NVIDIA_PROVIDER_SHA256,
    NVIDIA_SOURCE_COMMIT,
)


REFERENCE = ROOT / "docs/nvidia-gb200-command-reference.html"
TABLE = ROOT / "docs/nvidia-gb200-command-table.html"
SAFE_LIVE = ROOT / "docs/evidence/20260928T-nvidia-gb200-safe-live.json"
SECURITY_LIVE = ROOT / "docs/evidence/20260722T-nvidia-gb200-bios-password-live.json"
REFERENCE_ARTIFACT = "fb72a055-7867-4fc5-8dbd-36f060e81282 generated"
TABLE_ARTIFACT = "0f85aec2-e4bd-4f5e-8b1d-290ca5092718 generated"
BOOTSTRAP_SOURCE = (
    f"https://github.com/openbmc/phosphor-host-ipmid/blob/{NVIDIA_SOURCE_COMMIT}/"
    "oem/nvidia/bootstrap-credentials-oem-cmds.cpp"
)
BIOS_SOURCE = (
    f"https://github.com/openbmc/phosphor-host-ipmid/blob/{NVIDIA_SOURCE_COMMIT}/"
    "oem/nvidia/biosconfigcommands.cpp"
)


def _length(bounds: tuple[int | None, int | None]) -> str:
    low, high = bounds
    if low == high:
        return f"Exactly {low} payload bytes"
    if low == 0 and high is None:
        return "Variable length, including an empty value"
    return f"{low if low is not None else '?'}–{high if high is not None else '?'} payload bytes"


def _send(key: tuple[int, ...], command: dict) -> str:
    words = ["zipmi", "oem", "openbmc-nvidia"]
    if command["safety"] != "read-only":
        words.append("--unsafe")
    words.append(shlex.quote(command["name"]))
    fixed_prefix = len(key) - 2
    remaining = command["request_length"][0]
    if remaining is not None:
        remaining -= fixed_prefix
    if remaining:
        if key[:2] == (0x3C, 0x30):
            words.append("<descriptor_type:u8>")
        else:
            words.append(f"<{remaining} payload bytes>")
    return " ".join(words)


def _live_results() -> dict[tuple[int, int, bytes], dict]:
    if not SAFE_LIVE.exists():
        return {}
    evidence = json.loads(SAFE_LIVE.read_text())
    return {
        (int(item["netfn"], 0), int(item["cmd"], 0), bytes.fromhex(item["request"])): item
        for item in evidence["results"]
    }


def _operation_live(key: tuple[int, ...], results: dict) -> tuple[bool, str]:
    netfn, cmd = key[:2]
    if cmd == 0x37 and SECURITY_LIVE.exists():
        evidence = json.loads(SECURITY_LIVE.read_text())
        result = evidence["result"]
        return True, (
            f"{evidence['observed']} authenticated LAN proof: request {result['request']}, "
            f"CC {result['completionCode']}, {result['responseLength']}-byte response; planted "
            f"salt/hash matched and test password {evidence['offlineProof']['testPasswordRecovered']} "
            f"was recovered offline using {evidence['offlineProof']['algorithm']} with "
            f"{evidence['offlineProof']['iterations']} iterations"
        )
    requests = (bytes([1]), bytes([2])) if cmd == 0x30 else (bytes(key[2:]),)
    matches = [results.get((netfn, cmd, request)) for request in requests]
    if not all(matches):
        return False, "No retained live request for this operation"
    detail = "; ".join(
        f"request {item['request'] or '(empty)'} → CC {item['cc']}, data {item['response'] or '(empty)'}"
        for item in matches
    )
    return True, detail


def operation_rows() -> list[dict]:
    results = _live_results()
    rows = []
    for key, command in NVIDIA_COMMANDS.items():
        live, live_text = _operation_live(key, results)
        rows.append({
            "id": f"{key[0]:02x}/{key[1]:02x}" + (
                " data " + " ".join(f"{byte:02x}" for byte in key[2:]) if len(key) > 2 else ""
            ),
            "name": command["name"],
            "purpose": command["purpose"],
            "send": _send(key, command),
            "safety": command["safety"],
            "safety_note": command["side_effects"],
            "execution": (
                "Allowed by default" if command["safety"] == "read-only" else "Requires --unsafe"
            ),
            "request": {
                "status": "Complete", "length": _length(command["request_length"]),
                "summary": command["purpose"], "fields": command["request_fields"],
            },
            "response": {
                "status": "Complete", "length": _length(command["response_length"]),
                "summary": command["purpose"], "fields": command["response_fields"],
            },
            "privilege": command["privilege"],
            "interface": "Raw OEM NetFn 0x3c over authenticated IPMI; no IANA prefix",
            "availability": command["activation"],
            "completion_codes": command["completion_codes"],
            "live": live,
            "live_text": live_text,
            "evidence": command["evidence"],
            "confidence": command["confidence"],
        })
    return rows


def reference_page() -> dict:
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "NVIDIA GB200 OpenBMC OEM IPMI command reference",
        "scope": (
            "Complete operation contracts for all eight NVIDIA OEM registrations in the "
            "GB200 NVL OpenBMC provider shipped by the pinned zBMC image."
        ),
        "provenance": [
            ("Target", "NVIDIA GB200 NVL; OpenBMC machine <code>gb200nvl-obmc</code>"),
            ("OpenBMC build", "3.1.0-dev-294-g5d179dab3c; build 20260716192023"),
            ("Firmware SHA-256", f"<code>{NVIDIA_GB200_IMAGE_SHA256}</code>"),
            ("Provider", "<code>/usr/lib/ipmid-providers/libnvidia_ipmi_oem.so.0.1</code>"),
            ("Provider SHA-256", f"<code>{NVIDIA_PROVIDER_SHA256}</code>"),
            ("Provider ELF build ID", f"<code>{NVIDIA_PROVIDER_BUILD_ID}</code>"),
            ("Matching analyzed source commit", f"<code>{NVIDIA_SOURCE_COMMIT}</code>"),
            ("Inventory closure", "The image contains one NVIDIA OEM provider; its two constructors register these eight handlers."),
        ],
        "links": [{"label": "Compact NVIDIA GB200 command table", "href": "nvidia-gb200-command-table.html"}],
        "operations": operation_rows(),
        "commands": list(NVIDIA_COMMANDS),
        "gaps": (
            "The NVIDIA provider inventory, command bytes, privilege, request/response layouts, "
            "side effects, and named zipmi routes are closed. Physical host-interface dependencies "
            "can still make a correctly decoded command return a documented error in emulation."
        ),
        "live_evidence": (
            "The retained 2026-07-22 authenticated LAN proof covers Get BIOS Password and demonstrates "
            "offline recovery of the purpose-built test password Calvin. Set BIOS Password is not run "
            "during ordinary validation because it changes persistent credential state. The six safe "
            "Redfish Host Interface discovery commands remain source- and target-binary-proven unless "
            "the optional current safe evidence file is present."
        ),
        "sources": [
            f'<a href="{BOOTSTRAP_SOURCE}">OpenBMC NVIDIA Redfish Host Interface handlers</a>',
            f'<a href="{BIOS_SOURCE}">OpenBMC NVIDIA BIOS-password handlers</a>',
            '<a href="../zipmi/scapy_ipmi/oem/nvidia.py">Packaged contracts and codecs</a>',
            '<a href="evidence/20260722T-nvidia-gb200-bios-password-live.json">Retained BIOS-password disclosure proof</a>',
            *(['<a href="evidence/20260928T-nvidia-gb200-safe-live.json">Current safe live evidence</a>']
              if SAFE_LIVE.exists() else []),
        ],
    }


def compact_page() -> dict:
    rows = []
    for key, command in NVIDIA_COMMANDS.items():
        rows.append({
            "address": f"0x{key[0]:02x} / 0x{key[1]:02x}",
            "qualifier": (
                "data prefix " + " ".join(f"{byte:02x}" for byte in key[2:])
                if len(key) > 2 else "none"
            ),
            "handler": command["handler"],
            "privilege": command["privilege"],
            "request": _length(command["request_length"]),
            "activation": command["activation"],
            "evidence": command["evidence"],
        })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "NVIDIA GB200 OpenBMC compact OEM command table",
        "scope": "One row per NVIDIA OEM registration in the pinned GB200 provider binary.",
        "provenance": [
            ("Firmware SHA-256", f"<code>{NVIDIA_GB200_IMAGE_SHA256}</code>"),
            ("Provider SHA-256", f"<code>{NVIDIA_PROVIDER_SHA256}</code>"),
            ("Provider ELF build ID", f"<code>{NVIDIA_PROVIDER_BUILD_ID}</code>"),
        ],
        "metrics": [(8, "Firmware registrations"), (8, "Unique NetFn/Cmd addresses"),
                    (8, "Complete request contracts"), (8, "Complete response contracts")],
        "rows": rows,
        "sources": [
            {"href": BOOTSTRAP_SOURCE, "label": "OpenBMC NVIDIA bootstrap handlers"},
            {"href": BIOS_SOURCE, "label": "OpenBMC NVIDIA BIOS-password handlers"},
            {"href": "nvidia-gb200-command-reference.html", "label": "Detailed command reference"},
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
        print("NVIDIA GB200 generated documentation is stale", file=sys.stderr)
        return 1
    if not args.check:
        for path, _document in documents:
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
