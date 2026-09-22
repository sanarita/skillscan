from __future__ import annotations
import json

_ICON = {"allow": "✓ ALLOW", "review": "▲ REVIEW", "quarantine": "✗ QUARANTINE"}


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


def to_cli(result: dict) -> str:
    lines = [
        f"{_ICON[result['verdict']]}   score={result['score']}   kind={result['kind']}",
        f"target : {result['target']}",
    ]
    if result["hard_hit"]:
        lines.append("hard   : forced quarantine by " +
                     ", ".join(sorted(set(result["hard_reasons"]))) + " (★)")
    if result["region_counts"]:
        rc = ", ".join(f"{k}:{v}" for k, v in sorted(result["region_counts"].items()))
        lines.append(f"regions: {rc}")
    if result["findings"]:
        lines.append("")
        lines.append("  pts  region          context         finding / evidence")
        lines.append("  ---  --------------  --------------  ---------------------------")
        for f in result["findings"][:15]:
            star = "★" if f.get("hard") else " "
            note = f" [{f['note']}]" if f.get("note") else ""
            lines.append(
                f" {star}{f['points']:>4}  {f['region_kind']:<14}  {f.get('context', ''):<14}  "
                f"{f['id']}: {f['evidence']}{note}")
    else:
        lines.append("no findings")
    return "\n".join(lines)
