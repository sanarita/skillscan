"""Command-line interface for docscan.

Exit codes (matches skillscan's cli.py):
    0  clean (below --fail-on)
    1  a scanned target reached the --fail-on level
    2  usage / read / unsupported-file error
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import report
from .core import SUPPORTED, scan_path
from .scoring import VERDICT_ORDER


def _iter_targets(root: Path):
    if root.is_file():
        yield root
        return
    for ext in SUPPORTED:
        yield from root.rglob(f"*{ext}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="docscan",
        description="Indirect-prompt-injection scanner for PDF/DOCX files "
                     "(hidden/invisible text only -- not a macro or exploit scanner).")
    ap.add_argument("path", help="a .pdf/.docx file, or a tree to walk")
    ap.add_argument("--format", choices=["cli", "json"], default="cli")
    ap.add_argument("--fail-on", choices=["review", "quarantine"], default="quarantine")
    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    fail_idx = VERDICT_ORDER.index(args.fail_on)
    worst = 0
    results = []
    targets = list(_iter_targets(root)) if root.is_dir() else [root]
    if not targets:
        print(f"error: no {sorted(SUPPORTED)} files found under {root}", file=sys.stderr)
        return 2
    for target in targets:
        try:
            results.append(scan_path(target))
        except (OSError, ValueError) as e:
            print(f"error: cannot scan {target}: {e}", file=sys.stderr)
            return 2

    for result in results:
        worst = max(worst, VERDICT_ORDER.index(result["verdict"]))

    if args.format == "json":
        import json
        print(json.dumps(results[0] if len(results) == 1 else results,
                         ensure_ascii=False, indent=2))
    else:
        for i, result in enumerate(results):
            if i:
                print("\n" + "─" * 60)
            print(report.to_cli(result))

    return 1 if worst >= fail_idx else 0


if __name__ == "__main__":
    raise SystemExit(main())
