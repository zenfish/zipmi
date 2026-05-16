#!/usr/bin/env python3
"""
scripts/ansi_to_svg.py — turn captured ANSI terminal output into an SVG.

WHAT     Reads ANSI-coloured text on stdin, renders it to a terminal-window
         SVG on the path given as argv[1]. Used to freeze the `zipmi -d`
         wire trace into docs/img/ so the colours survive in the README
         (GitHub markdown renders committed SVG, never raw ANSI).

WHY      The -d hex dump is the headline feature. A pipe normally strips
         colour (colorize.color_enabled() is TTY-gated); FORCE_COLOR=1 keeps
         it, and rich converts that ANSI into a self-contained SVG — no PTY,
         no screenshot, regenerable via `make wire-trace`.

RUN      FORCE_COLOR=1 zipmi ... -d | python scripts/ansi_to_svg.py out.svg

RELATED  Makefile (wire-trace target), zipmi/scapy_ipmi/colorize.py
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.text import Text

TITLE = "zipmi — bmc info -d wire trace"
CMD = "zipmi -H 127.0.0.1 -p 16230 -U root -P calvin bmc info -d"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: ansi_to_svg.py OUT.svg  (ANSI text on stdin)",
              file=sys.stderr)
        return 2
    out = argv[1]
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")

    # width=100: rich wraps the long hex rows (the SEND/RECV blobs run
    # ~130-177 cols) onto continuation lines instead of producing a single
    # ~180-col canvas. GitHub fits the SVG to the ~880px text column, so
    # apparent font size ~= column_px / cols: halving the column count
    # roughly doubles the on-page font. Non-hex lines top out at ~94 cols,
    # so 100 leaves them un-wrapped.
    # color_system="truecolor" + force_terminal: the trace uses 24-bit
    # \x1b[38;2;R;G;Bm escapes. Without these rich sees a non-tty sink
    # (/dev/null), picks color_system=None, and records monochrome.
    console = Console(record=True, width=100, color_system="truecolor",
                      force_terminal=True, file=open("/dev/null", "w"))
    # Prompt line first, same font/flow as the trace (not the window
    # title) so it reads like a real shell session: `$ zipmi …`.
    prompt = Text("$ ", style="bold")
    prompt.append(CMD, style="bold")
    console.print(prompt)
    console.print(Text.from_ansi(raw))
    console.save_svg(out, title=TITLE)

    # rich emits only a viewBox. Stamp explicit pixel width/height from
    # it so the SVG has a real intrinsic size. width="100%" was wrong:
    # opened standalone an SVG is a replaced element, and percentage
    # width with no resolvable height collapses to the CSS default
    # (~300x150) -- the tiny clicked view. README links the image
    # straight to the raw file so the click bypasses GitHub's blob
    # viewer and renders this at full intrinsic size.
    _stamp_pixel_size(out)
    print(f">> wrote {out}", file=sys.stderr)
    return 0


def _stamp_pixel_size(path: str) -> None:
    """Add width/height/preserveAspectRatio to <svg>, from its viewBox."""
    svg = open(path, encoding="utf-8").read()
    head = svg.split(">", 1)[0]
    if "viewBox=" not in head or "width=" in head:
        return
    a, b = head.split('viewBox="0 0 ', 1)[1].split('"', 1)[0].split()
    w, h = round(float(a)), round(float(b))
    svg = svg.replace(
        "<svg ",
        f'<svg width="{w}" height="{h}" '
        'preserveAspectRatio="xMidYMid meet" ', 1)
    open(path, "w", encoding="utf-8").write(svg)
    return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
