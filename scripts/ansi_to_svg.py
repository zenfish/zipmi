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

    # rich emits only a viewBox. Make the root responsive (width=100%):
    # inline, GitHub's <img> still fits it to the README column; opened
    # standalone it fills the browser viewport instead of being boxed
    # *smaller* than the column (which is what fixed pixel width/height
    # caused -- GitHub's blob SVG viewer shrinks a fixed-size SVG).
    _make_responsive(out)
    print(f">> wrote {out}", file=sys.stderr)
    return 0


def _make_responsive(path: str) -> None:
    """Set width=100% on the <svg> root; viewBox keeps the aspect ratio."""
    svg = open(path, encoding="utf-8").read()
    head = svg.split(">", 1)[0]
    if "viewBox=" not in head or "width=" in head:
        return
    svg = svg.replace("<svg ", '<svg width="100%" ', 1)
    open(path, "w", encoding="utf-8").write(svg)
    return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
