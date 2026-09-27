# z-artifact: 154d6669-0648-4664-af4a-b14ecc9c6fc2
"""Shared HTML renderer for OEM Command Reference Standard v1."""

from __future__ import annotations

import html
import json


SAFETY = {
    "read-only": "Reads state and has no known persistent or service effect.",
    "sensitive": "Reads or changes credentials, trust, sessions, raw memory, firmware-control state, or other security-sensitive material.",
    "state-changing": "Changes configuration or runtime state without a known service interruption or data deletion.",
    "disruptive": "Can interrupt a service, session, device, or management connection.",
    "destructive": "Can erase data, reset configuration, or replace firmware or persistent state.",
    "unknown": "Available evidence does not establish the external effect.",
}
LAYOUT = ("Complete", "Partial", "Unknown", "Conflicting")
EXECUTION = ("Allowed by default", "Requires --unsafe", "No distinct named route")


def validate_reference(page: dict) -> None:
    """Reject incomplete renderer input at the documentation boundary."""
    required = {"title", "scope", "provenance", "links", "operations", "commands", "gaps", "live_evidence"}
    missing = required - page.keys()
    if missing:
        raise ValueError(f"missing page fields: {sorted(missing)}")
    ids = set()
    for operation in page["operations"]:
        if operation["id"] in ids:
            raise ValueError(f"duplicate operation id: {operation['id']}")
        ids.add(operation["id"])
        if operation["safety"] not in SAFETY:
            raise ValueError(f"unknown safety class: {operation['safety']}")
        if operation["request"]["status"] not in LAYOUT or operation["response"]["status"] not in LAYOUT:
            raise ValueError(f"unknown layout status: {operation['id']}")
        if operation["execution"] not in EXECUTION:
            raise ValueError(f"unknown execution policy: {operation['id']}")


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _badge(value: str) -> str:
    return f'<span class="badge {value}">{_e(value.title())}</span>'


def _fields(fields: list[dict] | None) -> str:
    if fields is None:
        return '<p class="muted">Field widths or meanings are not fully recovered.</p>'
    if not fields:
        return '<p class="muted">No fields.</p>'
    rows = "".join(
        f"<tr><td class=\"wire\">{_e(field['offset'])}</td><td class=\"wire\">{_e(field['name'])}</td>"
        f"<td>{_e(field['type'])}</td><td>{_e(field['meaning'])}</td></tr>"
        for field in fields
    )
    return ('<table class="field-table"><thead><tr><th>Offset</th><th>Name</th><th>Type / size</th>'
            f'<th>Required value or meaning</th></tr></thead><tbody>{rows}</tbody></table>')


def _layout(title: str, layout: dict) -> str:
    return (f'<div class="stack"><p><strong>Status:</strong> {_e(layout["status"])}</p>'
            f'<p><strong>Length:</strong> {_e(layout["length"])}</p>'
            f'<p><strong>Summary:</strong> <code>{_e(layout["summary"])}</code></p>'
            f'<details><summary>{title} fields</summary>{_fields(layout["fields"])}</details></div>')


def render_reference(page: dict, stylesheet_href: str = "assets/oem-command-reference.css") -> str:
    validate_reference(page)
    operations = page["operations"]
    safety_counts = {name: sum(op["safety"] == name for op in operations) for name in SAFETY}
    request_counts = {name: sum(op["request"]["status"] == name for op in operations) for name in LAYOUT}
    response_counts = {name: sum(op["response"]["status"] == name for op in operations) for name in LAYOUT}
    execution_counts = {name: sum(op["execution"] == name for op in operations) for name in EXECUTION}
    live_count = sum(op["live"] for op in operations)

    metrics = [
        (len(page["commands"]), "Top-level command addresses"),
        (len(operations), "Documented operations"),
        (f'{request_counts["Complete"]} / {request_counts["Partial"]} / {request_counts["Unknown"]} / {request_counts["Conflicting"]}', "Request layout: complete / partial / unknown / conflicting"),
        (f'{response_counts["Complete"]} / {response_counts["Partial"]} / {response_counts["Unknown"]} / {response_counts["Conflicting"]}', "Response layout: complete / partial / unknown / conflicting"),
        (f'{execution_counts["Allowed by default"]} / {execution_counts["Requires --unsafe"]} / {execution_counts["No distinct named route"]}', "Named operation route: default / --unsafe / no distinct route"),
        (live_count, "Operations with captured live requests"),
    ]
    metric_html = "".join(f'<div class="metric"><strong>{_e(value)}</strong>{_e(label)}</div>' for value, label in metrics)
    provenance = "".join(f'<tr><th scope="row">{_e(name)}</th><td>{value}</td></tr>' for name, value in page["provenance"])
    links = " · ".join(f'<a href="{_e(link["href"])}">{_e(link["label"])}</a>' for link in page["links"])
    definitions = "".join(
        f'<div class="panel">{_badge(name)} <strong>{safety_counts[name]} operations</strong><p>{_e(definition)}</p></div>'
        for name, definition in SAFETY.items()
    )

    operation_rows = []
    for index, op in enumerate(operations, 1):
        search = " ".join(str(value) for value in (op["send"], op["id"], op["name"], op["purpose"], op["safety"], op["evidence"])).lower()
        operation_rows.append(
            f'<tr data-search="{_e(search)}" data-safety="{_e(op["safety"])}" '
            f'data-request="{_e(op["request"]["status"])}" data-response="{_e(op["response"]["status"])}" '
            f'data-execution="{_e(op["execution"])}" data-live="{str(op["live"]).lower()}">'
            f'<td>{index}</td><td><code class="command">{_e(op["send"])}</code></td>'
            f'<th scope="row"><strong>{_e(op["name"])}</strong><div class="wire muted">{_e(op["id"])}</div><p>{_e(op["purpose"])}</p></th>'
            f'<td>{_badge(op["safety"])}{("<p class=\"muted\">" + _e(op["safety_note"]) + "</p>") if op.get("safety_note") else ""}</td>'
            f'<td>{_layout("Request", op["request"])}</td><td>{_layout("Response", op["response"])}</td>'
            f'<td class="stack"><p><strong>Privilege:</strong> {_e(op["privilege"])}</p><p><strong>Interface:</strong> {_e(op["interface"])}</p>'
            f'<p><strong>Available on this firmware:</strong> {_e(op["availability"])}</p><p><strong>Completion codes:</strong> <code>{_e(op["completion_codes"])}</code></p></td>'
            f'<td class="stack"><p><strong>Named operation route:</strong> {_e(op["execution"])}</p><p><strong>Build request from named fields:</strong> {_e(op["request_builder"])}</p>'
            f'<p><strong>Decode response into named fields:</strong> {_e(op["response_parser"])}</p><p><strong>Captured live request:</strong> {_e(op["live_text"])}</p>'
            f'<p><strong>Evidence:</strong> {_e(op["evidence"])}</p><p><strong>Confidence:</strong> {_e(op["confidence"])}</p></td></tr>'
        )

    command_rows = "".join(
        f'<tr><td class="wire">{_e(cmd["wire"])}</td><td><strong>{_e(cmd["handler"])}</strong><br><span class="muted">{_e(cmd["module"])}</span></td>'
        f'<td>{_e(cmd["availability"])}</td><td>{_e(cmd["privilege"])}</td><td>{_e(cmd["operation_count"])}</td><td>{_e(cmd["evidence"])}</td></tr>'
        for cmd in page["commands"]
    )
    safety_options = "".join(f'<option value="{name}">{name.title()}</option>' for name in SAFETY)
    layout_options = '<option value="">All</option>' + "".join(f'<option>{name}</option>' for name in ("Complete", "Partial", "Unknown", "Conflicting"))
    execution_options = '<option value="">All</option>' + "".join(f'<option>{name}</option>' for name in EXECUTION)
    source_items = "".join(f'<li>{item}</li>' for item in page["sources"])
    return f'''<!doctype html>
<!-- z-artifact: bbe82df6-3df8-4103-8612-72b359a7fdda generated -->
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page["title"])}</title><script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="{_e(stylesheet_href)}"></head><body><main>
<h1>{_e(page["title"])}</h1><p class="lede">{_e(page["scope"])}</p><p>{links}</p>
<section aria-labelledby="provenance"><h2 id="provenance">Firmware and evidence provenance</h2><div class="table-wrap"><table><tbody>{provenance}</tbody></table></div></section>
<section aria-labelledby="summary"><h2 id="summary">Comparable summary</h2><div class="summary">{metric_html}</div></section>
<section aria-labelledby="safety"><h2 id="safety">Safety definitions and counts</h2><p>Safety describes the known effect, not whether zipmi permits execution. When one recovered firmware row combines behaviors, the displayed class is the highest known impact and the row says so.</p><div class="definition-grid">{definitions}</div></section>
<section aria-labelledby="coverage"><h2 id="coverage">Inventory scope and known gaps</h2><div class="panel"><p>{_e(page["gaps"])}</p></div></section>
<section aria-labelledby="live"><h2 id="live">Live evidence</h2><div class="panel"><p>{_e(page["live_evidence"])}</p></div></section>
<section aria-labelledby="operations"><h2 id="operations">Operations</h2>
<div class="filters panel"><label>Search<input id="operation-filter" type="search" placeholder="zipmi command, operation, purpose, evidence"></label>
<label>Safety<select id="safety-filter"><option value="">All</option>{safety_options}</select></label>
<label>Request layout<select id="request-filter">{layout_options}</select></label>
<label>Response layout<select id="response-filter">{layout_options}</select></label>
<label>Execution<select id="execution-filter">{execution_options}</select></label>
<label><span>Live evidence</span><select id="live-filter"><option value="">All</option><option value="true">Live-tested only</option></select></label>
<button id="clear-filters" type="button">Clear filters</button></div>
<p id="operation-count" class="muted" aria-live="polite"></p>
<div class="table-wrap" role="region" aria-label="OEM operations" tabindex="0"><table class="operation-table"><caption>Commands to send, payload layouts, safety, availability, zipmi support, and evidence.</caption><thead><tr><th>#</th><th>Send with zipmi</th><th>Operation</th><th>Safety</th><th>Request data</th><th>Response data</th><th>Access &amp; availability</th><th>zipmi support &amp; evidence</th></tr></thead><tbody id="operation-rows">{"".join(operation_rows)}</tbody></table></div></section>
<section aria-labelledby="commands"><h2 id="commands">Top-level command addresses</h2><div class="table-wrap"><table><caption>Firmware dispatcher entries beneath the operations above.</caption><thead><tr><th>Command address</th><th>Firmware handler / module</th><th>Available on this firmware</th><th>Minimum privilege</th><th>Operations below it</th><th>Evidence</th></tr></thead><tbody id="command-rows">{command_rows}</tbody></table></div></section>
<section aria-labelledby="sources"><h2 id="sources">Sources</h2><ul>{source_items}</ul></section>
</main><script>
const ids=['operation-filter','safety-filter','request-filter','response-filter','execution-filter','live-filter'];
const controls=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
const rows=[...document.querySelectorAll('#operation-rows tr')],count=document.getElementById('operation-count');
function filterRows(){{let shown=0;for(const row of rows){{const visible=row.dataset.search.includes(controls['operation-filter'].value.toLowerCase())&&(!controls['safety-filter'].value||row.dataset.safety===controls['safety-filter'].value)&&(!controls['request-filter'].value||row.dataset.request===controls['request-filter'].value)&&(!controls['response-filter'].value||row.dataset.response===controls['response-filter'].value)&&(!controls['execution-filter'].value||row.dataset.execution===controls['execution-filter'].value)&&(!controls['live-filter'].value||row.dataset.live===controls['live-filter'].value);row.hidden=!visible;if(visible)shown++;}}count.textContent=`${{shown}} of ${{rows.length}} operations shown`;}}
for(const control of Object.values(controls))control.addEventListener(control.tagName==='INPUT'?'input':'change',filterRows);
document.getElementById('clear-filters').addEventListener('click',()=>{{for(const control of Object.values(controls))control.value='';filterRows();controls['operation-filter'].focus();}});filterRows();
</script></body></html>'''


def redirect_page(title: str, canonical_name: str, stylesheet_href: str = "assets/oem-command-reference.css") -> str:
    target = _e(canonical_name)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0; url={target}"><link rel="canonical" href="{target}"><link rel="stylesheet" href="{_e(stylesheet_href)}"><title>{_e(title)}</title></head><body><main><h1>{_e(title)}</h1><p>This compatibility URL has moved to <a href="{target}">{target}</a>.</p></main></body></html>'''
