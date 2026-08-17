#!/usr/bin/env python3
# what: doc/code symmetry guard for zipmi
# why: STATUS.md / README.md test counts and phase hashes drift from reality
#      between commits. Mechanical check beats promises.
# success: exit 0 = docs match code; exit 1 = mismatch (commit blocked).
# run: python scripts/check_doc_sync.py
# related: docs/STATUS.md, README.md, .git/hooks/pre-commit
"""Block commits that ship asymmetric docs/code state.

Checks:
  1. pytest --collect-only count matches "N passed in" / "N/N tests pass"
     strings in docs/STATUS.md and README.md.
  2. STATUS.md phase table has no "(this commit)" placeholder unless
     the commit is being made right now (best-effort: warn only).
  3. attacks/dell.py AttackPrimitive count matches docs/attacks-dell.md
     row count.
"""
from __future__ import annotations
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def collect_test_count() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", out.stdout)
    if not m:
        print("check_doc_sync: could not collect tests:", out.stderr, file=sys.stderr)
        sys.exit(2)
    return int(m.group(1))


def check_test_counts(actual: int) -> list[str]:
    errs = []
    status = (ROOT / "docs/STATUS.md").read_text()
    readme = (ROOT / "README.md").read_text()

    for label, text, path in [("STATUS.md", status, "docs/STATUS.md"),
                               ("README.md", readme, "README.md")]:
        for m in re.finditer(r"(\d+)\s+passed", text):
            n = int(m.group(1))
            if n != actual:
                errs.append(f"{path}: '{n} passed' but pytest collects {actual}")
        for m in re.finditer(r"(\d+)\s*/\s*(\d+)\s+tests?\s+pass", text):
            a, b = int(m.group(1)), int(m.group(2))
            if a != actual or b != actual:
                errs.append(f"{path}: '{a}/{b} tests pass' but pytest collects {actual}")
    return errs


def check_attack_count() -> list[str]:
    code = (ROOT / "zipmi/attacks/dell.py").read_text()
    statics = len(re.findall(r"^[A-Z][A-Z0-9_]*\s*=\s*AttackPrimitive\(", code, re.M))
    factories = len(re.findall(r"^def\s+\w+\([^)]*\)\s*->\s*AttackPrimitive", code, re.M))

    doc = (ROOT / "docs/attacks-dell.md").read_text()
    catalog = doc.split("## Catalog", 1)[1].split("##", 1)[0] if "## Catalog" in doc else ""
    factory_section = doc.split("## Factories", 1)[1].split("##", 1)[0] if "## Factories" in doc else ""
    cat_rows = sum(1 for line in catalog.splitlines()
                   if line.startswith("|") and "---" not in line and "Name" not in line and line.strip("| ").strip())
    fact_rows = sum(1 for line in factory_section.splitlines()
                    if line.startswith("|") and "---" not in line and "Function" not in line and line.strip("| ").strip())

    errs = []
    if statics != cat_rows:
        errs.append(f"attacks/dell.py has {statics} static AttackPrimitive(s) but "
                    f"docs/attacks-dell.md catalog has {cat_rows} rows")
    if factories != fact_rows:
        errs.append(f"attacks/dell.py has {factories} factory function(s) but "
                    f"docs/attacks-dell.md factories table has {fact_rows} rows")
    return errs


def check_placeholder() -> list[str]:
    status = (ROOT / "docs/STATUS.md").read_text()
    if "(this commit)" in status:
        return ["docs/STATUS.md still has '(this commit)' placeholder — "
                "after committing, replace with real hash and amend or follow up"]
    return []


def check_bmc_generation_documented() -> list[str]:
    """Every value in consts.BMC_GENERATION must appear in bmc-generations.md.

    Catches the class of failure where new user-facing dict entries get
    shipped (and printed by the CLI) without any prose in docs/ explaining
    what the labels mean. Operators who see "iDRAC9 Modular" in mc info
    output should be able to grep docs/ for an explanation.
    """
    sys.path.insert(0, str(ROOT))
    try:
        from zipmi.consts import BMC_GENERATION  # type: ignore
    except Exception as e:
        return [f"could not import BMC_GENERATION: {e}"]
    finally:
        sys.path.pop(0)

    doc_path = ROOT / "docs/bmc-generations.md"
    if not doc_path.exists():
        return [f"{doc_path.relative_to(ROOT)} missing — "
                f"every consts.BMC_GENERATION value must be explained there"]
    doc = doc_path.read_text()
    missing = [v for v in BMC_GENERATION.values() if v not in doc]
    if missing:
        return [f"docs/bmc-generations.md missing prose for: {missing!r}"]
    return []


def check_fuzz_inventory_consistent() -> list[str]:
    """Every zipmi/fuzz/*.py module must appear in cmd_fuzz_list AND docs/fuzz.md.

    Catches the failure mode where a fuzz module is written but never
    wired to the CLI (orphaned module — the situation that motivated
    this whole branch of work) or wired but never documented.
    """
    fuzz_dir = ROOT / "zipmi/fuzz"
    modules = {p.stem for p in fuzz_dir.glob("*.py")
               if p.stem not in ("__init__", "__pycache__")}
    cli = (ROOT / "zipmi/cli/zipmi.py").read_text()
    doc = (ROOT / "docs/fuzz.md").read_text() if (ROOT / "docs/fuzz.md").exists() else ""
    errs = []
    for mod in modules:
        if f"zipmi.fuzz.{mod}" not in cli:
            errs.append(f"zipmi/fuzz/{mod}.py not imported in zipmi/cli/zipmi.py "
                        f"(orphaned module — wire it or delete it)")
        if f"zipmi.fuzz.{mod}" not in doc:
            errs.append(f"zipmi/fuzz/{mod}.py not mentioned in docs/fuzz.md")
    return errs


def check_cli_fields_documented() -> list[str]:
    """Every '<field name> :' line printed by mc info must appear in docs.

    The mc info verb is the most-grepped CLI surface; new fields shipped
    there without doc references are the failure mode that motivated this
    check. Greps zipmi/cli/zipmi.py for `print(f"<Label>` patterns and
    asserts each <Label> appears in some docs/*.md.
    """
    cli = (ROOT / "zipmi/cli/zipmi.py").read_text()
    # Only pull labels from the cmd_mc_info function block.
    if "def cmd_mc_info" not in cli:
        return []
    body = cli.split("def cmd_mc_info", 1)[1].split("\ndef ", 1)[0]
    labels = re.findall(r'print\(f"([A-Z][A-Za-z][^:]*?)\s*:', body)
    docs_blob = ""
    for p in (ROOT / "docs").rglob("*.md"):
        docs_blob += p.read_text()
    docs_blob += (ROOT / "README.md").read_text()
    missing = [lbl.strip() for lbl in labels if lbl.strip() not in docs_blob]
    if missing:
        return [f"mc info prints fields with no docs reference: {missing!r}"]
    return []


def check_oem_count() -> list[str]:
    """README's <!--OEM-COUNT-->N<!--/OEM-COUNT--> must match the live OEM total.

    The count drifts as vendor dispatch tables grow. Regenerate with
    `make readme-stats` (scripts/update_readme_stats.py).
    """
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"<!--OEM-COUNT-->(\d+)<!--/OEM-COUNT-->", readme)
    if not m:
        return ["README.md: OEM-COUNT marker missing — "
                "wrap the OEM total in <!--OEM-COUNT-->N<!--/OEM-COUNT-->"]
    sys.path.insert(0, str(ROOT))
    try:
        from zipmi.cli.oem_cmds import oem_command_totals  # type: ignore
        _known, named = oem_command_totals()
    except Exception as e:
        return [f"could not compute OEM totals: {e}"]
    finally:
        sys.path.pop(0)
    if int(m.group(1)) != named:
        return [f"README.md OEM-COUNT is {m.group(1)} but live total is {named} "
                f"— run `make readme-stats`"]
    return []


def main() -> int:
    actual = collect_test_count()
    errs: list[str] = []
    errs += check_test_counts(actual)
    errs += check_attack_count()
    errs += check_placeholder()
    errs += check_bmc_generation_documented()
    errs += check_fuzz_inventory_consistent()
    errs += check_cli_fields_documented()
    errs += check_oem_count()
    if errs:
        print("doc/code symmetry violation:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        print("\nfix docs to match code, then commit.", file=sys.stderr)
        return 1
    print(f"doc sync OK ({actual} tests, attack catalog matches).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
