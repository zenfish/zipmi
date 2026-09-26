#!/usr/bin/env python3
"""Generate the firmware-bound Lenovo XCC OEM IPMI HTML reference."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "zipmi" / "data" / "sources"
CATALOG = SOURCES / "lenovo-xcc-commands.json"
CONTRACTS = SOURCES / "lenovo-xcc-operation-contracts.json"
OUTPUT = ROOT / "docs" / "lenovo-xcc-command-reference.html"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def length(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        low, high = value.get("min"), value.get("max")
        return f"{low if low is not None else '?'}..{high if high is not None else '?'}"
    return "?"


def fields(items: list[dict]) -> str:
    if not items:
        return '<span class="text-slate-400">opaque or empty</span>'
    parts = []
    for item in items:
        detail = item["kind"]
        if "length" in item:
            detail += f"[{item['length']}]"
        if "constant" in item:
            detail += f" = 0x{item['constant']:02x}"
        parts.append(f"<li><code>{esc(item['name'])}</code>: {esc(detail)}</li>")
    return '<ul class="list-disc pl-5">' + "".join(parts) + "</ul>"


def marker() -> str:
    if not OUTPUT.exists():
        return ""
    match = re.search(r"<!-- z-artifact: ([^>]+) -->", OUTPUT.read_text(errors="ignore"))
    return f"<!-- z-artifact: {match.group(1)} -->\n" if match else ""


catalog = json.loads(CATALOG.read_text())
contracts_doc = json.loads(CONTRACTS.read_text())
commands = catalog["commands"]
contracts = contracts_doc["contracts"]
pairs = {(item["netfn"], item["cmd"]) for item in commands}
request_codecs = sum(bool(item.get("requestCodec")) for item in contracts)
response_codecs = sum(bool(item.get("responseCodec")) for item in contracts)
safe = sum(item["effect"] == "safe" for item in contracts)
unsafe = len(contracts) - safe
unresolved = [item for item in contracts if item.get("codecState") in {
    "unresolved", "conflicting-evidence", "partial", "raw-exact"
}]

command_rows = []
for index, item in enumerate(commands, 1):
    prefix = " ".join(f"{byte:02x}" for byte in item["prefix"]) or "—"
    operations = item.get("operations", [])
    operation_text = "<br>".join(
        f"<strong>{esc(op['operation'])}</strong> [{esc(op['selector'] or 'base')}]: "
        f"{esc(op['request'])} → {esc(op['response'])}; CC {esc(op['completionCodes'] or 'generic')}"
        for op in operations
    ) or '<span class="text-amber-700">No decoded leaf contract; activation is retained explicitly.</span>'
    search = " ".join((item["name"], item["handler"], item["dispatch"], item["purpose"])).lower()
    command_rows.append(f"""<tr class="border-b align-top" data-row="{esc(search)}">
<td class="p-2 text-xs">{index}</td><td class="p-2 font-mono text-xs whitespace-nowrap">0x{item['netfn']:02x}/0x{item['cmd']:02x}<br>prefix {esc(prefix)}</td>
<td class="p-2 min-w-72"><strong>{esc(item['name'])}</strong><br><span class="text-xs text-slate-500">{esc(item['dispatch'])} · privilege {esc(item['privilege'])}</span><p class="mt-1 text-sm">{esc(item['purpose'])}</p></td>
<td class="p-2 min-w-80 text-xs">{esc(item['handler'])}<br><strong>Length admission:</strong> {esc(item['requestLengthRules'])}<br><strong>Remote:</strong> {esc(item['remoteRestriction'])}</td>
<td class="p-2 min-w-[36rem] text-xs">{operation_text}</td>
<td class="p-2 min-w-64 text-xs"><strong>{esc(item['sideEffect'])}</strong><br>{esc(item['evidenceState'])} / {esc(item['confidence'])}<br>{esc(item['source'])}</td></tr>""")

contract_rows = []
for index, item in enumerate(contracts, 1):
    selector = " ".join(f"{byte:02x}" for byte in item.get("selector", [])) or "—"
    req_codec = "yes" if item.get("requestCodec") else "no"
    rsp_codec = "yes" if item.get("responseCodec") else "no"
    badge = "bg-emerald-100 text-emerald-900" if item["effect"] == "safe" else "bg-rose-100 text-rose-900"
    search = " ".join((item["name"], item["purpose"], item["effect"], item.get("activation", ""))).lower()
    contract_rows.append(f"""<tr class="border-b align-top" data-contract="{esc(search)}">
<td class="p-2 text-xs">{index}</td><td class="p-2 font-mono text-xs whitespace-nowrap">0x{item['netfn']:02x}/0x{item['cmd']:02x}<br>selector {esc(selector)} @ {esc(item.get('selectorOffset'))}</td>
<td class="p-2 min-w-72"><strong>{esc(item['name'])}</strong><p class="mt-1 text-sm">{esc(item['purpose'])}</p><span class="mt-2 inline-block rounded px-2 py-1 text-xs font-semibold {badge}">{esc(item['effect'])}</span></td>
<td class="p-2 min-w-96 text-xs"><strong>{esc(length(item.get('requestLength')))} bytes:</strong> {esc(item['request'])}<details><summary>Fields</summary>{fields(item.get('requestFields', item.get('bodyFields', [])))}</details></td>
<td class="p-2 min-w-96 text-xs"><strong>{esc(length(item.get('responseLength')))} bytes after CC:</strong> {esc(item['response'])}<details><summary>Fields</summary>{fields(item.get('responseFields', []))}</details></td>
<td class="p-2 min-w-96 text-xs"><strong>Privilege:</strong> {esc(item.get('privilege', 'standard Get=User / Set=Admin'))}<br><strong>Channel:</strong> {esc(item.get('channel', 'standard LAN configuration channel'))}<br><strong>Activation:</strong> {esc(item.get('activation', 'XCC 6.92 OEMLANInit channel-data handler'))}<br><strong>Side effects:</strong> {esc(item['sideEffects'])}<details><summary>Completion codes</summary><pre>{esc(json.dumps(item.get('completionCodes', []), indent=2))}</pre></details></td>
<td class="p-2 min-w-72 text-xs"><strong>Codec:</strong> request {req_codec}, response {rsp_codec} ({esc(item['codecState'])})<br><strong>Evidence:</strong> {esc(item.get('evidence', 'Lenovo public contract + XCC 6.92 handler activation'))}<br><a class="text-blue-700 underline" href="{esc(item.get('source', 'https://pubs.lenovo.com/xcc/get_set_lan_config_parameter'))}">source</a></td></tr>""")

document = f"""<!doctype html>
{marker()}<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lenovo XCC 6.92 OEM IPMI reference</title><script src="https://cdn.tailwindcss.com"></script>
<style>body{{font-family:ui-sans-serif,system-ui,sans-serif}}code,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}summary{{cursor:pointer;color:#1d4ed8}}th{{position:sticky;top:0;z-index:1}}</style></head>
<body class="bg-slate-100 text-slate-900"><main class="mx-auto max-w-[1900px] bg-white p-5 md:p-10">
<h1 class="text-3xl font-bold">Lenovo XCC 6.92 OEM IPMI reference</h1>
<p class="mt-3">Firmware-bound to <strong>Newyork-pass1</strong>. Full rootfs SquashFS SHA-256 <code>2aaedcb6c5939efabd49ac4da0a8066e17c5c3dea356ad33ad0d9246c4b192c2</code>; <code>libipmi.so</code> SHA-256 <code>b72294cd8a10699e2cd3827dd1b4aa0a13943c483332af0ceae8ba603cf17485</code>.</p>
<div class="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-6"><div class="rounded bg-blue-50 p-4"><strong class="text-2xl">{len(commands)}</strong> top-level identities</div><div class="rounded bg-blue-50 p-4"><strong class="text-2xl">{len(pairs)}</strong> top-level pairs</div><div class="rounded bg-violet-50 p-4"><strong class="text-2xl">{len(contracts)}</strong> exact operation contracts</div><div class="rounded bg-emerald-50 p-4"><strong class="text-2xl">{request_codecs}</strong> request codecs</div><div class="rounded bg-emerald-50 p-4"><strong class="text-2xl">{response_codecs}</strong> response codecs</div><div class="rounded bg-amber-50 p-4"><strong class="text-2xl">{safe}/{unsafe}</strong> safe/unsafe contracts</div></div>
<section class="mt-6 rounded border border-blue-300 bg-blue-50 p-4"><h2 class="font-bold">Closed denominator</h2><p>Three active top-level surfaces are reconciled: 192 C++ registration occurrences (166 identities), 175 legacy admission rows, and the 134-row core request table. Their OEM union is {len(commands)} exact identities / {len(pairs)} pairs. The core table adds <code>30/e2</code>, <code>30/e3</code>, and <code>3a/c7</code>. Dormant registrar libraries shipped in the SquashFS are excluded only because <code>pl_newyork</code> does not load them. Standard LAN commands <code>0c/01</code> and <code>0c/02</code> expand into selector operations below rather than new top-level OEM pairs.</p></section>
<section class="mt-4 rounded border border-amber-300 bg-amber-50 p-4"><h2 class="font-bold">Bounded unknowns</h2><p>{len(unresolved)} operation records intentionally retain raw, partial, conflicting, or unresolved fields. Notable boundaries are inactive Avocent routes <code>3a/49</code>, <code>3a/4a</code>, and <code>3a/4d</code>; hostname public-doc/binary termination disagreement; PSoC FRU-ID and MTU endian; D4 priority-zero meaning; D6 mode enumeration; and delegated selector leaves not yet promoted to fixed codecs. Every non-safe or schema-unbounded named request requires <code>--unsafe</code>.</p></section>
<section class="mt-4 rounded border border-rose-300 bg-rose-50 p-4"><h2 class="font-bold">Authorization finding</h2><p>A separate ReadOnly, IPMI-only account authenticated over LAN at User privilege 2 and successfully invoked <code>2e/cc 5e2b000a01ff000000</code>, resetting XCC configuration to defaults on an isolated <code>snapshot=on</code> guest. The response was <code>CC00 5e2b000a0100</code>, including success status <code>00</code>. The OSA outer dispatcher requires User; its inner table labels this leaf Admin, but the exact 6.92 handler does not read the inner privilege byte. The same session received <code>D4</code> from a genuinely Admin-gated control. The target-side audit and JSON evidence are retained in the zBMC Lenovo box reference. zipmi's <code>--unsafe</code> guard prevents accidental named execution; it does not change firmware authorization.</p></section>
<section class="mt-4 rounded border border-emerald-300 bg-emerald-50 p-4"><h2 class="font-bold">Safe live proof</h2><p>zBMC run <code>20260926T180101Z-a368af09-d224-4a10-b6f6-74c5e3d2490d</code> reached READY after a required 83-second stable interval. zipmi 0.5.0 then executed all 32 mechanically synthesizable fixed-request read-only contracts. Twenty-nine returned <code>CC00</code>; Board Hardware Revision returned <code>CCCE</code>, Front USB Enable Get returned <code>CCD5</code>, and inactive firmware-only LAN selector D2 returned <code>CCCC</code>. The retained <a class="text-blue-700 underline" href="evidence/20260926T180101Z-lenovo-xcc-safe-live.json">evidence artifact</a> records every exact request and response; no unsafe operation was sent.</p></section>
<section class="mt-6"><h2 class="text-2xl font-bold">Exact operation contracts</h2><label class="mt-3 block font-semibold" for="contract-filter">Filter contracts</label><input id="contract-filter" class="mt-2 w-full rounded border p-3" placeholder="name, address, effect, activation"><div class="mt-4 overflow-auto" role="region" aria-label="Lenovo operation contracts" tabindex="0"><table class="w-full border-collapse text-left"><thead class="bg-slate-200 text-xs"><tr><th class="p-2">#</th><th class="p-2">Wire</th><th class="p-2">Operation</th><th class="p-2">Request</th><th class="p-2">Response</th><th class="p-2">Safety / activation</th><th class="p-2">zipmi / evidence</th></tr></thead><tbody id="contract-rows">{''.join(contract_rows)}</tbody></table></div></section>
<section class="mt-10"><h2 class="text-2xl font-bold">Top-level identity inventory</h2><label class="mt-3 block font-semibold" for="command-filter">Filter identities</label><input id="command-filter" class="mt-2 w-full rounded border p-3" placeholder="name, handler, dispatch, subsystem"><div class="mt-4 overflow-auto" role="region" aria-label="Lenovo top-level command identities" tabindex="0"><table class="w-full border-collapse text-left"><thead class="bg-slate-200 text-xs"><tr><th class="p-2">#</th><th class="p-2">Wire</th><th class="p-2">Identity</th><th class="p-2">Handler / admission</th><th class="p-2">Decoded operations</th><th class="p-2">Effect / evidence</th></tr></thead><tbody id="command-rows">{''.join(command_rows)}</tbody></table></div></section>
<section class="mt-10 border-t pt-5 text-sm"><h2 class="font-bold">Primary sources</h2><ul class="list-disc pl-6"><li><a class="text-blue-700 underline" href="https://pubs.lenovo.com/xcc/oem_ipmi_commands">Lenovo XCC OEM IPMI commands</a></li><li><a class="text-blue-700 underline" href="https://pubs.lenovo.com/xcc/get_set_lan_config_parameter">Lenovo XCC LAN parameters</a></li><li><a class="text-blue-700 underline" href="https://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/ipmi-intelligent-platform-mgt-interface-spec-2nd-gen-v2-0-spec-update.pdf">IPMI v2.0 standard LAN framing</a></li><li>Exact XCC 6.92 binaries named in each evidence row.</li></ul></section>
</main><script>for(const [inputId,rowSelector,attribute] of [['contract-filter','#contract-rows tr','data-contract'],['command-filter','#command-rows tr','data-row']]){{document.getElementById(inputId).addEventListener('input',event=>{{const query=event.target.value.toLowerCase();document.querySelectorAll(rowSelector).forEach(row=>row.hidden=!row.getAttribute(attribute).includes(query));}});}}</script></body></html>"""

OUTPUT.write_text(document)
print(f"wrote {OUTPUT} ({len(commands)} identities, {len(contracts)} contracts)")
