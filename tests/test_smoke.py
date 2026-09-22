"""Regression tests over the labeled corpus (v0.4).
Includes the 12 adversarial specimens from the v0.2 self-review and the
5 frontmatter parser-differential specimens from the v0.3 review."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from skillscan.core import scan_path  # noqa: E402

CORPUS = Path(__file__).parent / "corpus"

def test_every_malicious_quarantined():
    for d in sorted((CORPUS / "malicious").iterdir()):
        r = scan_path(d)
        assert r["verdict"] == "quarantine", (d.name, r["verdict"], r["score"])

def test_no_benign_quarantined():
    for d in sorted((CORPUS / "benign").iterdir()):
        assert scan_path(d)["verdict"] != "quarantine", d.name

def test_frontmatter_injection_caught():
    assert scan_path(CORPUS / "malicious/fm-injection")["verdict"] == "quarantine"

def test_powershell_installer_caught():
    assert scan_path(CORPUS / "malicious/install-powershell")["hard_hit"]

def test_japanese_not_confusable():
    r = scan_path(CORPUS / "benign/jp-terms")
    assert r["verdict"] == "allow", r["score"]

def test_bom_and_folded_parse():
    r = scan_path(CORPUS / "benign/bom-folded")
    assert r["frontmatter"].get("name") == "bom-folded"

def test_frontmatter_differentials_caught():
    for name in ("fm-fold-colon", "fm-block-comment", "fm-block-dash", "fm-escape", "fm-zw-smuggle"):
        assert scan_path(CORPUS / "malicious" / name)["verdict"] == "quarantine", name

def test_frontmatter_edge_cases_clean():
    r = scan_path(CORPUS / "benign/fm-edge-cases")
    assert r["verdict"] == "allow" and not r["findings"], r["findings"]
    assert r["frontmatter"]["metadata"] == {"version": "1.2", "author": "Jane, Doe"}

def test_rule_fixes_typography_evasion_caught():
    # curly apostrophe, double space, line break, '.env' inside a sentence
    r = scan_path(CORPUS / "malicious/typography-evasion")
    assert r["verdict"] == "quarantine"
    assert {"conceal_from_user", "override_prior", "exfil_secret", "send_to_url"} <= {f["id"] for f in r["findings"]}

def test_rule_fixes_no_false_positive_on_onboarding():
    # 'You are now ready', 'new instructions for', 'Spread the token list ... forward'
    r = scan_path(CORPUS / "benign/onboarding-notes")
    assert r["verdict"] == "allow" and not r["findings"], r["findings"]

if __name__ == "__main__":
    for k, fn in list(globals().items()):
        if k.startswith("test_"): fn()
    print("all tests passed")
