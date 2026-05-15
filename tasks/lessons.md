# Lessons

Format: `YYYY-MM-DD | trigger | wrong move | right move | why`

2026-05-15 | resuming BMC/NCSI research on live iDRAC6 | re-probed 192.168.0.23 NCSI from scratch, rediscovered March-2026 finding, burned a probe round-trip | read ~/phd/bmc/ research corpus (esp. dell-ncsi-shared-nic-investigation.md) BEFORE touching live hardware | prior work already pinned the blocker; live re-probe added nothing but latency
2026-05-15 | quoting a path from a doc | said "/tmp/dell-bmc-kernel.bin" as if local; it was on the BMC (tmpfs, wiped on reboot) | state where a path is rooted; copy volatile BMC artifacts to ~/phd/ at extraction time | lost the original kernel dump to a BMC reboot; had to re-extract
2026-05-15 | extracting kernel from /dev/mem | used count= from doc's "~4.2MB" prose, truncated last 325KB (incl. kernel-data) | compute exact bounds from /proc/iomem (text+data start/end), bs=512 sector-aligned | every byte of a forensic dump is load-bearing; prose sizes are approximate
2026-05-15 | user wants to install + run scripts | repeatedly pushed pipx/venv as "the way"; pipx isolates the lib so `import zipmi` fails in user scripts | clone→one command (./install.sh): global pip, auto-fallback to --user on PEP668; lib importable + CLI on PATH | user means the normal python flow, not app-sandbox; pipx is CLI-only
