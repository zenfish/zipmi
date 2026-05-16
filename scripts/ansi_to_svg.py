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

import re
import sys

from rich.console import Console
from rich.text import Text

TITLE = "zipmi bmc info -d  (vs. virtual BMC)"


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
    console.print(Text.from_ansi(raw))
    console.save_svg(out, title=TITLE)

    # rich emits only a viewBox, no width/height -> renderers (incl.
    # GitHub's raw/blob view when you click through) size it to whatever
    # box they have, which is also narrow, so it never gets bigger.
    # Stamp explicit pixel dims from the viewBox: inline still scales to
    # the column (max-width:100%), but click-through now opens full size.
    _stamp_intrinsic_size(out)
    print(f">> wrote {out}", file=sys.stderr)
    return 0


def _stamp_intrinsic_size(path: str) -> None:
    """Add width/height attrs to the <svg> root, derived from its viewBox."""
    svg = open(path, encoding="utf-8").read()
    m = re.search(r'<svg\b[^>]*\bviewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    if not m:
        return
    w, h = round(float(m.group(1))), round(float(m.group(2)))
    if "width=" not in svg.split(">", 1)[0]:
        svg = svg.replace("<svg ", f'<svg width="{w}" height="{h}" ', 1)
        open(path, "w", encoding="utf-8").write(svg)
    return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
