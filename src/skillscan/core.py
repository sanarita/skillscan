"""Orchestration: turn a path into a scan result. Pure functions, no I/O side
effects beyond reading the target files."""
from __future__ import annotations
from pathlib import Path

from . import detectors, scoring
from .extractors import frontmatter, shell
from .context import Context
from .extractors.hidden import extract_regions, Region


def scan_text(skill_text: str, install_text: str | None = None) -> dict:
    fm = frontmatter.parse(skill_text)
    body = fm.body
    regions = extract_regions(body)
    ctx = Context(body)

    findings: list[dict] = []

    # Frontmatter is loaded for EVERY skill regardless of trigger, so it is a
    # high-value injection target. v0.4: scan decoded values + unparsed lines +
    # the raw text, all NFKC/invisible-normalized, so a parser differential
    # (folded lines, '#' lines, escapes, zero-width) cannot hide a payload.
    fm_text = frontmatter.scan_text(fm)
    if fm_text.strip():
        fm_regions = [Region("frontmatter", fm_text, pos=0)]
        findings += detectors.detect_injection(fm_regions, Context(fm_text))

    findings += detectors.detect_intent(regions)
    findings += detectors.detect_injection(regions, ctx)
    for t in frontmatter.analyze(fm):     # triggers / parse gaps / obfuscation -> B axis
        where = f"{t['key']}: " if t["key"] else ""
        findings.append({"axis": "B", "id": t["id"], "weight": t["severity"] * 2,
                         "region_kind": "frontmatter", "context": "directive",
                         "evidence": f"{where}{t['evidence']}  ({t['detail']})"})

    if install_text is not None:
        findings += detectors.detect_install(
            shell.commands(install_text), shell.pipelines(install_text))

    scored = scoring.score(findings)
    verdict = scoring.classify(scored)
    return {
        "frontmatter": fm.data,
        "frontmatter_issues": {"gaps": fm.gaps, "anomalies": [k for k, _ in fm.anomalies]},
        "verdict": verdict,
        "score": scored["total"],
        "per_axis": scored["per_axis"],
        "hard_hit": scored["hard_hit"],
        "hard_reasons": scored["hard_reasons"],
        "findings": scored["contributions"],
    }


INSTALL_NAMES = ("install.sh", "install.ps1", "setup.sh", "bootstrap.sh")


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8-sig", errors="replace")


def scan_path(path: str | Path) -> dict:
    p = Path(path)
    skill_text, skill_path = "", None
    install_dir: Path | None = None
    if p.is_dir():
        for name in ("SKILL.md", "skill.md"):
            if (p / name).exists():
                skill_path = p / name
                skill_text = _read(skill_path)
                break
        install_dir = p
    elif p.name.lower() in INSTALL_NAMES:
        skill_path = None
    else:
        skill_path = p
        skill_text = _read(p)
        install_dir = p.parent

    if install_dir is not None:
        found = [install_dir / n for n in INSTALL_NAMES if (install_dir / n).exists()]
    else:
        found = [p]
    install_text = "\n".join(_read(f) for f in found) if found else None

    result = scan_text(skill_text, install_text)
    result["target"] = str(skill_path or p)
    result["scanned_install"] = install_text is not None
    return result
