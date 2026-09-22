"""Orchestration: path -> scan result. Pure inspection, nothing is executed
and no macro/embedded-object/exploit analysis is attempted (see package
docstring for the scope boundary)."""
from __future__ import annotations
from pathlib import Path

from . import scoring
from .extractors import docx as docx_extractor
from .extractors import pdf as pdf_extractor

SUPPORTED = {".docx": docx_extractor, ".pdf": pdf_extractor}


def scan_regions(regions, target: str, kind: str) -> dict:
    findings = scoring.detect(regions)
    scored = scoring.score(findings)
    verdict = scoring.classify(scored)
    return {
        "target": target,
        "kind": kind,
        "verdict": verdict,
        "score": scored["total"],
        "hard_hit": scored["hard_hit"],
        "hard_reasons": scored["hard_reasons"],
        "findings": scored["contributions"],
        "region_counts": _region_counts(regions),
    }


def _region_counts(regions) -> dict:
    counts: dict[str, int] = {}
    for r in regions:
        if r.text.strip():
            counts[r.kind] = counts.get(r.kind, 0) + 1
    return counts


def scan_path(path: str | Path) -> dict:
    p = Path(path)
    ext = p.suffix.lower()
    extractor = SUPPORTED.get(ext)
    if extractor is None:
        raise ValueError(
            f"unsupported extension {ext!r} -- docscan handles {sorted(SUPPORTED)} only "
            f"(indirect-prompt-injection text scan, not a general file-safety scanner)")
    regions = extractor.extract(p)
    return scan_regions(regions, target=str(p), kind=ext.lstrip("."))
