"""Signal detectors (v0.2: context-aware).

Each finding: {axis, id, weight, region_kind, context, evidence, hard?}
- context = "directive" | "example:<kind>" (code_fence, quote, table ...)
Evidence is truncated so a report never reproduces a full payload.
"""
from __future__ import annotations
import json
import re
from importlib import resources

from ..context import Context
from ..normalizer import fold_for_match
from ..extractors.hidden import Region, REGION_MULTIPLIER


def _load(name: str) -> dict:
    with resources.files("skillscan.rules").joinpath(name).open(encoding="utf-8") as f:
        return json.load(f)


_INTENT = _load("intent.json")
_INJECTION = _load("injection.json")
_INSTALL = _load("install.json")
_INJ = [(p["id"], p["weight"], p.get("exfil", False), re.compile(p["regex"])) for p in _INJECTION["patterns"]]
_INS = [(p["id"], p["weight"], p.get("hard", False), p.get("scope", "command"),
         re.compile(p["regex"])) for p in _INSTALL["patterns"]]


def _clip(s: str, n: int = 80) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"


def _ctx_label(ctx: Context, pos: int) -> str:
    k = ctx.kind_at(pos)
    return f"example:{k}" if k else "directive"


# Short/ambiguous intent tokens need word boundaries (rce vs source, c2 vs EC2).
_WB_TOKENS = {"rce", "c2", "suid", "privesc", "opsec", "pivot", "beacon",
              "keylog", "uac bypass", "amsi bypass"}
_WB_CACHE = {t: re.compile(r"\b" + re.escape(t) + r"\b", re.I) for t in _WB_TOKENS}


def _term_present(term: str, low: str) -> bool:
    rx = _WB_CACHE.get(term)
    return bool(rx.search(low)) if rx else (term in low)


def detect_intent(regions: list[Region]) -> list[dict]:
    """A-axis: one finding per category, deduplicated across regions.
    Intent is CONTEXT (tags), not proof — scoring caps its total."""
    hits: dict[str, set] = {}
    for r in regions:
        low = r.text.lower()
        for cat, terms in _INTENT["categories"].items():
            for t in terms:
                if _term_present(t, low):
                    hits.setdefault(cat, set()).add(t)
    return [{"axis": "A", "id": f"intent:{cat}", "weight": _INTENT["base_weight"],
             "region_kind": "visible", "context": "tag",
             "evidence": f"{cat}: {', '.join(sorted(ts)[:3])}"}
            for cat, ts in sorted(hits.items())]


def detect_injection(regions: list[Region], ctx: Context) -> list[dict]:
    findings = []
    for r in regions:
        text = fold_for_match(r.text)   # same length -> offsets still valid for ctx
        for pid, weight, exfil, rx in _INJ:
            if r.kind == "visible":
                # Score the strongest occurrence: a directive beats an example.
                best = None
                for m in rx.finditer(text):
                    label = _ctx_label(ctx, m.start())
                    if best is None or (label == "directive" and best[0] != "directive"):
                        best = (label, m.group(0))
                    if label == "directive":
                        break
                if best:
                    findings.append({"axis": "B", "id": pid, "weight": weight,
                                     "region_kind": "visible", "context": best[0],
                                     "exfil": exfil, "evidence": _clip(best[1])})
            else:
                m = rx.search(text)
                if m:
                    findings.append({"axis": "B", "id": pid, "weight": weight,
                                     "region_kind": r.kind, "context": _ctx_label(ctx, r.pos),
                                     "exfil": exfil, "evidence": _clip(m.group(0))})
    return findings


def detect_install(commands: list[str], pipelines: list[str]) -> list[dict]:
    findings = []
    for pid, weight, hard, scope, rx in _INS:
        for line in (pipelines if scope == "pipeline" else commands):
            if rx.search(line):
                findings.append({"axis": "C", "id": pid, "weight": weight, "hard": hard,
                                 "region_kind": "visible", "context": "directive",
                                 "evidence": _clip(line)})
                break
    return findings


def region_multiplier(kind: str) -> float:
    return REGION_MULTIPLIER.get(kind, 1.0)
