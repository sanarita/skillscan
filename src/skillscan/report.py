"""Rendering. JSON for machines/CI; a compact, explainable table for humans."""
from __future__ import annotations
import json

_ICON = {"allow": "✓ ALLOW", "review": "▲ REVIEW", "quarantine": "✗ QUARANTINE"}
_AXIS = {"A": "intent", "B": "injection", "C": "install"}


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


def to_cli(result: dict) -> str:
    fm = result.get("frontmatter", {})
    name = fm.get("name", "(no name)")
    lines = [
        f"{_ICON[result['verdict']]}   score={result['score']}   "
        f"[A:{result['per_axis']['A']} B:{result['per_axis']['B']} C:{result['per_axis']['C']}]",
        f"target : {result['target']}",
        f"skill  : {name}"
        + ("   install.sh: scanned" if result.get("scanned_install") else ""),
    ]
    if result["hard_hit"]:
        lines.append("hard   : forced quarantine by " + ", ".join(sorted(set(result.get("hard_reasons", [])))) + " (★)")
    if result["findings"]:
        lines.append("")
        lines.append("  pts  axis        region        context         finding / evidence")
        lines.append("  ---  ----------  ------------  --------------  ---------------------------")
        for f in result["findings"][:15]:
            star = "★" if f.get("hard") else " "
            lines.append(
                f" {star}{f['points']:>4}  {_AXIS[f['axis']]:<10}  "
                f"{f['region_kind']:<12}  {f.get('context', ''):<14}  {f['id']}: {f['evidence']}")
    else:
        lines.append("no findings")
    return "\n".join(lines)
