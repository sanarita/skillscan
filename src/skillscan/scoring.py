"""Scoring + classification (v0.2).

points = weight x region_multiplier x context_multiplier
- context_multiplier = 0.35 for matches inside examples (code fence, quote,
  table, blockquote, inline code); 1.0 for directive text.
- A-axis (intent) is capped at A_CAP points in total: security docs mention
  attack terms constantly (774/818 real skills hit A in v0.1), so intent alone
  must never push a skill to review. It only adds weight to real B/C signals.
- Hard (forced quarantine): any `hard` install rule, or a B-axis hit in a
  HIDDEN region that is not inside an example.
"""
from __future__ import annotations
from .context import EXAMPLE_MULTIPLIER
from .detectors import region_multiplier
from .extractors.hidden import HIDDEN_KINDS

# Decoded/hidden channels are never legitimately "just an example": keep full weight.
_NO_DOWNWEIGHT = HIDDEN_KINDS

THRESHOLDS = {"review": 6, "quarantine": 14}
VERDICT_ORDER = ["allow", "review", "quarantine"]
A_CAP = 3.0


def _is_example(f: dict) -> bool:
    return f.get("context", "").startswith("example")


def score(findings: list[dict]) -> dict:
    per_axis = {"A": 0.0, "B": 0.0, "C": 0.0}
    contributions, hard_hit, hard_reasons = [], False, []
    for f in findings:
        mult = region_multiplier(f["region_kind"])
        if _is_example(f) and f["region_kind"] not in _NO_DOWNWEIGHT:
            # Exfil directives are rarely "just quoted examples" in a real doc,
            # so they keep most of their weight even inside a quote/fence.
            mult *= 0.7 if f.get("exfil") else EXAMPLE_MULTIPLIER
        pts = f["weight"] * mult
        is_hard = bool(f.get("hard")) or (
            f["axis"] == "B" and f["region_kind"] in HIDDEN_KINDS)
        if is_hard:
            hard_hit = True
            hard_reasons.append(f["id"])
        per_axis[f["axis"]] += pts
        contributions.append({**f, "multiplier": round(mult, 2), "points": round(pts, 2),
                              "hard": is_hard})
    per_axis["A"] = min(per_axis["A"], A_CAP)
    total = round(sum(per_axis.values()), 2)
    contributions.sort(key=lambda c: c["points"], reverse=True)
    return {"total": total, "per_axis": {k: round(v, 2) for k, v in per_axis.items()},
            "hard_hit": hard_hit, "hard_reasons": hard_reasons, "contributions": contributions}


def classify(scored: dict) -> str:
    if scored["hard_hit"] or scored["total"] >= THRESHOLDS["quarantine"]:
        return "quarantine"
    if scored["total"] >= THRESHOLDS["review"]:
        return "review"
    return "allow"
