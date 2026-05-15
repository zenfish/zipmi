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

TITLE = "zipmi bmc info -d  (vs. virtual BMC)"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: ansi_to_svg.py OUT.svg  (ANSI text on stdin)",
              file=sys.stderr)
        return 2
    out = argv[1]
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")

    # width=180: the -d hex rows are wide (~177 visible cols); a narrower
    # console would wrap the trace and wreck the alignment we're showing off.
    # color_system="truecolor" + force_terminal: the trace uses 24-bit
    # \x1b[38;2;R;G;Bm escapes. Without these rich sees a non-tty sink
    # (/dev/null), picks color_system=None, and records monochrome.
    console = Console(record=True, width=180, color_system="truecolor",
                      force_terminal=True, file=open("/dev/null", "w"))
    console.print(Text.from_ansi(raw))
    console.save_svg(out, title=TITLE)
    print(f">> wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
