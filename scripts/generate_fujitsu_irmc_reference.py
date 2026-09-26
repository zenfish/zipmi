#!/usr/bin/env python3
"""Render zipmi's installed iRMC S6 OEM command catalog as HTML."""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zipmi.cli.oem_cmds import _vendor_listing
from zipmi.scapy_ipmi.oem.fujitsu import FUJITSU_OPERATIONS, FUJITSU_RECORDS, FUJITSU_TOP_LEVEL


OUTPUT = ROOT / "docs/fujitsu-irmc-s6-command-reference.html"
LIVE = json.loads((ROOT / "docs/evidence/20260926T204500Z-fujitsu-irmc-safe-live-22.json").read_text())


def esc(value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return html.escape(str(value), quote=True)


listing = _vendor_listing("fujitsu")
assert len(FUJITSU_RECORDS) == 148 and len(FUJITSU_OPERATIONS) == 232
assert len(FUJITSU_TOP_LEVEL) == 128
assert sum(op.status == "decoded" for op in FUJITSU_OPERATIONS if op.netfn == 0x2E) == 61
assert sum(op.status == "unknown" for op in FUJITSU_OPERATIONS) == 4
assert len(listing) == 367
assert len(LIVE["results"]) == 22
assert sum(row.get("completionCode") == 0 for row in LIVE["results"]) == 21
top = [(key, row) for key, row in listing.items() if len(key) == 2]
assert len(top) == 135

top_rows = []
for key, info in sorted(top):
    wire = f"{key[0]:02x}/{key[1]:02x}"
    top_rows.append(
        f'<tr class="border-b align-top" data-search="{esc((wire + info["name"] + info["desc"]).lower())}">'
        f'<td class="p-2 font-mono whitespace-nowrap">{wire}</td>'
        f'<td class="p-2">{esc(info["name"])}<div class="text-xs text-slate-500">{esc(info["lib"])}</div></td>'
        f'<td class="p-2">{esc(info["priv"])} · {esc(info["request"])}</td>'
        f'<td class="p-2">{esc(info["security"])}</td>'
        f'<td class="p-2">{"parent only" if not info["runnable"] else "--unsafe required"}</td></tr>'
    )

operation_rows = []
for op in FUJITSU_OPERATIONS:
    key = (op.netfn, op.cmd, *op.prefix)
    info = listing[key]
    wire = f"{op.netfn:02x}/{op.cmd:02x} " + " ".join(f"{byte:02x}" for byte in op.prefix)
    gate = "safe fixed read" if not op.requires_unsafe else (
        "host-interface only" if not op.runnable else "--unsafe required"
    )
    operation_rows.append(
        f'<tr class="border-b align-top" data-search="{esc((wire + info["name"] + op.effect).lower())}">'
        f'<td class="p-2 font-mono whitespace-nowrap">{esc(wire)}</td>'
        f'<td class="p-2">{esc(info["name"])}<div class="text-xs text-slate-500">{esc(op.source)}</div></td>'
        f'<td class="p-2">{esc(op.privilege)} · {esc(op.request)}</td>'
        f'<td class="p-2">{esc(op.response)}</td>'
        f'<td class="p-2">{esc(op.effect)}</td>'
        f'<td class="p-2">{esc(op.status)} · {gate}<div class="text-xs text-slate-500">{esc(op.activation)}</div></td></tr>'
    )

document = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zipmi Fujitsu iRMC S6 OEM IPMI reference</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-50 text-slate-900"><main class="mx-auto max-w-7xl px-5 py-10">
<p class="text-sm font-bold uppercase tracking-widest text-blue-700">zipmi · Fujitsu iRMC S6 02.63S</p>
<h1 class="mt-3 text-4xl font-bold">Fujitsu OEM IPMI command reference</h1>
<p class="mt-4 max-w-4xl leading-7">For the RX2540 M7 image only. The recovered table is closed at 148 active records: 135 NetFn/command pairs or 138 LUN-aware identities. zipmi exposes 135 top-level names and 232 selector/group operations. Of the 228 selector leaves, 61 are decoded, 163 partial, and four unknown. A name is not a claim that an unsafe or partial payload has a structured codec.</p>
<div class="mt-6 grid gap-3 sm:grid-cols-3"><div class="rounded bg-blue-100 p-4"><strong class="text-2xl">367</strong><div>named CLI entries</div></div><div class="rounded bg-emerald-100 p-4"><strong class="text-2xl">22</strong><div>safe fixed-read operations</div></div><div class="rounded bg-amber-100 p-4"><strong class="text-2xl">228</strong><div>2e selector candidates</div></div></div>
<section class="mt-6 rounded border border-amber-400 bg-amber-50 p-5"><h2 class="text-xl font-bold">Execution model and limits</h2><p class="mt-2 leading-7">Named selector operations prepend their proven Fujitsu IANA and selector bytes. Twenty-two read-only selectors are constrained to a four-byte request and can run without <code>--unsafe</code>. Other runnable names require <code>--unsafe</code> pending individual safe promotion; this includes some decoded standard reads as well as state-changing or partial commands. The two group-52 Redfish bootstrap operations are Admin/channel-0f host-interface routes and are not runnable over zipmi's LAN transport. Parent 2e and 2c dispatch names cannot be sent without selecting a leaf. Three distinct LUN-3 FRU handlers are documented in the <a class="text-blue-700 underline" href="https://github.com/zenfish/zbmc/blob/main/boxes/irmc-fujitsu/irmc-s6-oem-reference.html">firmware reference</a> but not exposed as LAN names after the target returned C0 on LUN 3.</p><pre class="mt-4 overflow-auto rounded bg-slate-900 p-4 text-sm text-slate-100"><code>zipmi oem fujitsu
zipmi -H &lt;irmc&gt; -U admin -C 17 oem irmc IRMCGetLastPowerOnReason0115
zipmi -H &lt;irmc&gt; -U admin -C 17 oem fujitsu --unsafe &lt;named-operation&gt; &lt;body-bytes&gt;</code></pre></section>
<section class="mt-6 rounded border border-rose-400 bg-rose-50 p-5"><h2 class="text-xl font-bold">High-impact findings</h2><ul class="mt-3 list-disc space-y-2 pl-6"><li><code>2e/01</code> is admitted at User privilege and multiplexes power reads with state-changing selectors 17, 1b, 1c, and 20.</li><li><code>2c/02 52 a5</code> can create and return user credentials on the host channel; it is never a safe DCMI power read.</li><li><code>34/38–39</code> persists configuration and has a statically proved undersized-page copy path.</li><li><code>2e/F5</code> selectors 52, a5, and f8 reach I2C write/read, persistent POH reset, and user deletion respectively; flash and raw PECI routes also remain high-impact. These are static findings, not live probes.</li></ul><p class="mt-3">See the <a class="text-blue-700 underline" href="https://github.com/zenfish/zbmc/blob/main/boxes/irmc-fujitsu/irmc-s6-oem-reference.html">zBMC binary-evidence reference</a> for handler addresses, platform gates, and the distinction between decoded and partial leaf contracts.</p></section>
<section class="mt-6 rounded border border-emerald-400 bg-emerald-50 p-5"><h2 class="text-xl font-bold">Safe live proof</h2><p class="mt-2 leading-7">The fresh iRMC guest run <code>{esc(LIVE['runId'])}</code> reached required-service READY. Twenty-two reviewed read-only four-byte requests were sent: 21 returned CC00, while 2e/e0 selector 00 returned device CC01; none had a transport error. The named zipmi path for power selector 15 also returned CC00. <a class="text-blue-700 underline" href="evidence/20260926T204500Z-fujitsu-irmc-safe-live-22.json">Exact bytes and completion codes</a> are retained. No state-changing request was sent.</p></section>
<section class="mt-8"><h2 class="text-2xl font-bold">Top-level dispatch names</h2><label class="mt-3 block" for="top-filter">Filter commands</label><input id="top-filter" class="mt-2 w-full rounded border p-3" placeholder="wire or handler"><div class="mt-4 overflow-auto" role="region" aria-label="Top-level dispatch names" tabindex="0"><table class="min-w-full text-left text-sm"><thead class="bg-slate-200"><tr><th class="p-2">Wire</th><th class="p-2">Handler</th><th class="p-2">Privilege / request</th><th class="p-2">Safety</th><th class="p-2">Execution</th></tr></thead><tbody id="top-rows">{''.join(top_rows)}</tbody></table></div></section>
<section class="mt-10"><h2 class="text-2xl font-bold">Selector and group operations</h2><label class="mt-3 block" for="operation-filter">Filter operations</label><input id="operation-filter" class="mt-2 w-full rounded border p-3" placeholder="wire, name, effect"><div class="mt-4 overflow-auto" role="region" aria-label="Selector and group operations" tabindex="0"><table class="min-w-full text-left text-sm"><thead class="bg-slate-200"><tr><th class="p-2">Wire</th><th class="p-2">Name / source</th><th class="p-2">Request</th><th class="p-2">Response</th><th class="p-2">Effect</th><th class="p-2">Evidence / gate</th></tr></thead><tbody id="operation-rows">{''.join(operation_rows)}</tbody></table></div></section>
<section class="mt-10 rounded border p-5"><h2 class="text-xl font-bold">Source pin</h2><p class="mt-2 leading-7">iRMC S6 02.63S <code>libipmipdkcmds.so.1.53.20</code> SHA-256 <code>35839f7ab40993898666425d50e18654d68791c7dfe3bb5a3c3496e4daa23804</code>. The packaged command table SHA-256 is <code>6c25538d508e398135855d59550148b3fd93cdcc045bc9556e4f79c335f72dfa</code>. The operation catalog retains source JSON hashes. Public references: <a class="text-blue-700 underline" href="https://support.ts.fujitsu.com/Search/SWP1267156.asp">Fujitsu iRMC S6 Concepts &amp; Interfaces</a> and <a class="text-blue-700 underline" href="https://github.com/chu11/freeipmi-mirror">FreeIPMI's Fujitsu definitions</a>; older-generation selectors are not assumed to work on this image.</p></section>
</main><script>for(const [input,body] of [['top-filter','top-rows'],['operation-filter','operation-rows']]){{document.getElementById(input).addEventListener('input',e=>{{const q=e.target.value.toLowerCase();for(const row of document.getElementById(body).rows)row.hidden=!row.dataset.search.includes(q)}})}}</script></body></html>
'''
if "--check" in sys.argv[1:]:
    assert OUTPUT.read_text() == document, "Fujitsu zipmi reference is out of sync"
    print("Fujitsu zipmi reference OK: 367 named entries")
else:
    OUTPUT.write_text(document)
    print("wrote Fujitsu zipmi reference: 367 named entries")
