# z-artifact: 0bd01976-c09c-417e-b2ab-b21b2c476c70
"""Shared compact disclosures for generated OEM tables."""

from __future__ import annotations

import html


DISCLOSURE_BYTES = 80


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def field(
    value: object,
    summary: str = "Show full value",
    *,
    tag: str | None = None,
    class_name: str = "",
) -> str:
    """Escape a value and collapse it when its UTF-8 representation is long."""
    text = str(value)
    body = escape(text)
    if tag:
        class_attr = f' class="{class_name}"' if class_name else ""
        body = f"<{tag}{class_attr}>{body}</{tag}>"
    if len(text.encode("utf-8")) <= DISCLOSURE_BYTES:
        return body
    if not tag:
        body = f"<span>{body}</span>"
    return (
        '<details class="cell-disclosure" data-bulk-disclosure>'
        f'<summary>{escape(summary)}</summary>{body}</details>'
    )


__all__ = ["DISCLOSURE_BYTES", "escape", "field"]
