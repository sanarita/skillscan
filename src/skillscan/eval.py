"""Evaluation harness.

Labeled corpus layout:
    tests/corpus/benign/<skill>/SKILL.md      -> expected: allow (review tolerated)
    tests/corpus/malicious/<skill>/...        -> expected: quarantine (review = partial catch)

Optional --external <dir>: a real-world skill library treated as
"presumed benign" (unverified labels). We report its quarantine/review
rates as a false-positive proxy, not as ground truth.

Usage:
    uv run python -m skillscan.eval tests/corpus [--external path/to/skills]
"""
from __future__ import annotations
import argparse
import collections
import json
from pathlib import Path

from .core import scan_path


def _skill_dirs(root: Path):
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        if (d / "SKILL.md").exists() or (d / "install.sh").exists():
            yield d


def eval_labeled(corpus: Path) -> dict:
    rows = []
    for label in ("benign", "malicious"):
        base = corpus / label
        if not base.exists():
            continue
        for d in _skill_dirs(base):
            r = scan_path(d)
            rows.append({"label": label, "name": d.name, "verdict": r["verdict"], "score": r["score"]})

    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    caught_q = sum(r["verdict"] == "quarantine" for r in mal)
    caught_any = sum(r["verdict"] != "allow" for r in mal)
    fp_q = sum(r["verdict"] == "quarantine" for r in ben)
    fp_any = sum(r["verdict"] != "allow" for r in ben)
    return {
        "rows": rows,
        "malicious_n": len(mal), "benign_n": len(ben),
        "recall_quarantine": caught_q / len(mal) if mal else None,
        "recall_review_or_worse": caught_any / len(mal) if mal else None,
        "benign_quarantined": fp_q, "benign_flagged": fp_any,
    }


def eval_external(root: Path) -> dict:
    c = collections.Counter()
    q = []
    for d in _skill_dirs(root):
        r = scan_path(d)
        c[r["verdict"]] += 1
        if r["verdict"] == "quarantine":
            q.append((r["score"], d.name))
    n = sum(c.values())
    return {
        "n": n, "verdicts": dict(c),
        "quarantine_rate": c["quarantine"] / n if n else None,
        "review_rate": c["review"] / n if n else None,
        "quarantined": [name for _, name in sorted(q, reverse=True)],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="skillscan-eval")
    ap.add_argument("corpus")
    ap.add_argument("--external")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    out = {"labeled": eval_labeled(Path(a.corpus))}
    if a.external:
        out["external"] = eval_external(Path(a.external))

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    L = out["labeled"]
    print("== labeled corpus ==")
    for r in L["rows"]:
        ok = (r["label"] == "benign" and r["verdict"] == "allow") or \
             (r["label"] == "malicious" and r["verdict"] == "quarantine")
        mark = "ok " if ok else ("~  " if r["verdict"] == "review" else "NG ")
        print(f"  {mark} {r['label']:9} {r['verdict']:10} {r['score']:6}  {r['name']}")
    print(f"  recall (quarantine)        : {L['recall_quarantine']:.0%}  ({L['malicious_n']} malicious)")
    print(f"  recall (review or worse)   : {L['recall_review_or_worse']:.0%}")
    print(f"  benign quarantined/flagged : {L['benign_quarantined']}/{L['benign_flagged']} of {L['benign_n']}")
    if "external" in out:
        E = out["external"]
        print("\n== external (presumed benign, unverified) ==")
        print(f"  n={E['n']}  verdicts={E['verdicts']}")
        print(f"  quarantine rate {E['quarantine_rate']:.1%}   review rate {E['review_rate']:.1%}")
        for name in E["quarantined"][:10]:
            print(f"    quarantined: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
