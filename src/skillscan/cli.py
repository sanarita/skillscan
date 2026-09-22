"""Command-line interface.

Exit codes make it usable as a CI / pre-commit gate:
    0  clean (below --fail-on)
    1  a scanned target reached the --fail-on level
    2  usage / read error
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import report
from .core import scan_path, INSTALL_NAMES
from .scoring import VERDICT_ORDER


def _iter_targets(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("SKILL.md"):
        yield p.parent            # scan the skill dir so install.sh is picked up
    # standalone install.sh with no sibling SKILL.md
    for name in INSTALL_NAMES:
        for q in root.rglob(name):
            if not (q.parent / "SKILL.md").exists():
                yield q


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skillscan",
        description="Static risk scanner for Claude SKILL.md files and their install.sh.")
    ap.add_argument("path", help="a SKILL.md, a skill directory, or a tree to walk")
    ap.add_argument("--format", choices=["cli", "json"], default="cli")
    ap.add_argument("--fail-on", choices=["review", "quarantine"], default="quarantine",
                    help="exit non-zero if any target reaches this verdict (default: quarantine)")
    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    fail_idx = VERDICT_ORDER.index(args.fail_on)
    worst = 0
    results = []
    for target in _iter_targets(root):
        try:
            results.append(scan_path(target))
        except OSError as e:
            print(f"error: cannot read {target}: {e}", file=sys.stderr)
            return 2

    for result in results:
        worst = max(worst, VERDICT_ORDER.index(result["verdict"]))

    if args.format == "json":
        import json
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for i, result in enumerate(results):
            if i:
                print("\n" + "─" * 60)
            print(report.to_cli(result))

    return 1 if worst >= fail_idx else 0


if __name__ == "__main__":
    raise SystemExit(main())
