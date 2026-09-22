"""Executable documentation for rules/injection.json.

Every rule's `examples.match` must match and `examples.no_match` must not,
so the prose in the rule file cannot drift from what the regex does. Any
future edit to a regex (e.g. fixing a `known_gaps` entry) must keep these
green or update them deliberately.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from skillscan.normalizer import fold_for_match  # noqa: E402

RULES = Path(__file__).resolve().parents[1] / "src/skillscan/rules/injection.json"
CATEGORIES = {"override", "role", "address", "disclosure", "concealment", "exfiltration", "tool"}


def _patterns():
    return json.loads(RULES.read_text(encoding="utf-8"))["patterns"]


def test_ids_unique_and_fields_present():
    ps = _patterns()
    assert len({p["id"] for p in ps}) == len(ps)
    for p in ps:
        for key in ("id", "category", "weight", "description", "regex", "examples", "known_gaps"):
            assert key in p, (p.get("id"), key)
        assert p["category"] in CATEGORIES, p["id"]
        assert p["examples"]["match"] and p["examples"]["no_match"], p["id"]
        assert "known_gaps" in p and isinstance(p["known_gaps"], list), p["id"]


def test_no_literal_space_between_words():
    """Convention: \\s+ between words, so double spaces / line breaks cannot evade."""
    for p in _patterns():
        assert not re.search(r"[A-Za-z)] [A-Za-z(]", p["regex"]), p["id"]


def test_fold_is_length_preserving():
    s = "Don\u2019t \u201cquote\u201d\u00a0x\u3000y"
    assert len(fold_for_match(s)) == len(s)
    assert fold_for_match(s) == "Don't \"quote\" x y"


def test_examples_match():
    for p in _patterns():
        rx = re.compile(p["regex"])
        for s in p["examples"]["match"]:
            assert rx.search(fold_for_match(s)), (p["id"], "should match", s)


def test_examples_no_match():
    for p in _patterns():
        rx = re.compile(p["regex"])
        for s in p["examples"]["no_match"]:
            assert not rx.search(fold_for_match(s)), (p["id"], "should NOT match", s)


if __name__ == "__main__":
    for k, fn in list(globals().items()):
        if k.startswith("test_"):
            fn()
    print("all rule tests passed")
