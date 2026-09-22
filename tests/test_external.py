"""Regression tests over tests/corpus_docs/external (samples from ipi-guard).

These are NOT synthetic specimens written for docscan: they were authored
separately, and docscan v1.0 missed 3 of their 5 attacks. Pinning their
verdicts guards against regressions on data the scanner was not tuned on.

Every file in the folder must have an entry in EXPECTED, so adding a sample
without deciding its label fails loudly instead of being silently ignored.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from skillscan.docscan.core import SUPPORTED, scan_path  # noqa: E402

EXTERNAL = Path(__file__).parent / "corpus_docs" / "external"

# file name -> (expected verdict, finding ids that must be present)
EXPECTED = {
    "attack_docx_camouflage_white.docx": ("review",     {"hidden_text_present"}),
    "attack_docx_hidden_vanish.docx":    ("quarantine", {"override_prior"}),
    "attack_docx_metadata.docx":         ("quarantine", {"override_prior_ja", "address_ai_ja"}),
    "attack_docx_white_text.docx":       ("quarantine", {"override_prior_ja", "address_ai_ja"}),
    "attack_pdf_white_text.pdf":         ("quarantine", {"override_prior"}),
    "clean_docx_report.docx":            ("allow",      set()),
    "clean_pdf_report.pdf":              ("allow",      set()),
}

pytestmark = pytest.mark.skipif(not EXTERNAL.exists(),
                                reason="external samples not present in this checkout")


def _files():
    return sorted(p for p in EXTERNAL.iterdir() if p.suffix.lower() in SUPPORTED)


def test_every_external_file_is_labeled():
    unlabeled = [p.name for p in _files() if p.name not in EXPECTED]
    assert not unlabeled, f"add these to EXPECTED with a verdict: {unlabeled}"


def test_no_expected_file_missing():
    present = {p.name for p in _files()}
    missing = sorted(set(EXPECTED) - present)
    assert not missing, f"listed in EXPECTED but not found: {missing}"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_external_verdict(name):
    path = EXTERNAL / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    verdict, must_have = EXPECTED[name]
    r = scan_path(path)
    ids = {f["id"] for f in r["findings"]}
    assert r["verdict"] == verdict, (name, r["verdict"], r["score"], sorted(ids))
    assert must_have <= ids, (name, "missing findings", sorted(must_have - ids))
    if verdict == "allow":
        assert not ids, (name, sorted(ids))
