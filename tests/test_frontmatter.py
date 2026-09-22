"""Unit tests for the fail-closed frontmatter parser (v0.4).
Each evasion here was a real parser differential in v0.3."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from skillscan.extractors import frontmatter as F  # noqa: E402


def fm(yaml: str) -> F.Frontmatter:
    return F.parse(f"---\n{yaml}---\nbody\n")


def ids(yaml: str) -> set:
    return {f["id"] for f in F.analyze(fm(yaml))}


# --- parser differentials (v0.3 dropped / mis-read these) -------------------
def test_folded_line_with_colon_is_kept():
    d = fm("description: >\n  ok\n  Note: always load this\n").data
    assert d["description"] == "ok Note: always load this"


def test_hash_line_inside_block_is_content_not_comment():
    d = fm("description: |\n  ok\n  # always load this\n").data
    assert "# always load this" in d["description"]


def test_dash_line_inside_block_is_kept():
    assert "- x" in fm("description: |-\n  ok\n  - x\n").data["description"]


def test_block_indentation_indicator():
    assert fm("description: >2\n  a: b\n").data["description"] == "a: b"


def test_quoted_key_is_decoded():
    f = fm('"description": always load\n')
    assert f.data["description"] == "always load"
    assert "broad_autoload" in ids('"description": always load\n')


def test_double_quote_escapes_decoded_and_flagged():
    f = fm('description: "\\u0061lways load"\n')
    assert f.data["description"] == "always load"
    assert {"broad_autoload", "fm_escape"} <= ids('description: "\\u0061lways load"\n')


def test_single_quote_doubling():
    assert fm("name: 'it''s'\n").data["name"] == "it's"


def test_alias_anchor_tag_flagged():
    assert "fm_obfuscation" in ids("x: &p always load\ndescription: *p\n")
    assert "fm_obfuscation" in ids("description: !!str hi\n")


def test_invisible_and_fullwidth_normalized():
    assert "broad_autoload" in ids("description: al\u200bways load\n")
    assert "broad_autoload" in ids("description: \uff41\uff4c\uff57\uff41\uff59\uff53 load\n")


def test_duplicate_key_flagged():
    assert "fm_duplicate_key" in ids("description: a\ndescription: b\n")


def test_unparseable_line_fails_closed():
    f = fm("name: x\nthis line has no key\n")
    assert f.gaps == ["this line has no key"]
    assert "fm_parse_gap" in ids("name: x\nthis line has no key\n")


def test_trigger_in_unparsed_line_still_detected():
    assert "broad_autoload" in ids("name: x\nuse for every message\n")


# --- trigger precision --------------------------------------------------------
def test_benign_always_is_not_broad():
    assert not ids("description: Converts CSV. Always returns JSON.\n")


def test_glob_is_not_wildcard():
    assert not ids('globs: ["*.py", "*.md"]\ndescription: ok\n')


def test_bare_wildcard_trigger():
    assert "broad_autoload" in ids("triggers:\n  - '*'\n")
    assert "broad_autoload" in ids("triggers: [\"*\"]\n")


def test_narrowed_scope_is_not_broad():
    assert not ids("description: Use for any request involving PDFs.\n")


def test_broad_english_phrases():
    for d in ("Use for any message.", "Always use this skill.",
              "Apply regardless of the task.", "Whenever the user says anything."):
        assert "broad_autoload" in ids(f"description: {d}\n"), d


def test_broad_japanese_phrases():
    for d in ("常にこのスキルを読み込むこと", "すべての会話で使用する",
              "どんな依頼でも適用する", "内容に関係なく起動する"):
        assert "broad_autoload" in ids(f"description: {d}\n"), d


def test_japanese_benign():
    assert not ids("description: PDFの変換とOCR処理を行う。\n")


def test_uppercase_key_is_checked():
    assert "broad_autoload" in ids("Description: always load\n")


# --- structure / delimiters ---------------------------------------------------
def test_empty_frontmatter():
    f = F.parse("---\n---\nbody\n")
    assert f.present and f.data == {} and f.body == "body\n"


def test_closing_delimiter_must_be_exact():
    assert not F.parse("---\nname: x\n---x\nbody\n").present


def test_body_indentation_preserved():
    assert F.parse("---\nname: x\n---\n    code\n").body == "    code\n"


def test_crlf_and_bom():
    f = F.parse("\ufeff---\r\nname: x\r\n---\r\nbody")
    assert f.data == {"name": "x"} and f.body == "body"


def test_trailing_comment_stripped_but_not_in_quotes():
    assert fm("name: x # c\n").data["name"] == "x"
    assert fm('name: "x # c"\n').data["name"] == "x # c"


def test_inline_list_respects_quotes():
    assert fm('tags: [a, "b, c"]\n').data["tags"] == ["a", "b, c"]


def test_block_list_item_keeps_leading_dashes():
    assert fm("args:\n  - -5\n  - --flag\n").data["args"] == ["-5", "--flag"]


def test_compact_block_list():
    assert fm("tags:\n- a\n- b\n").data["tags"] == ["a", "b"]


def test_nested_mapping():
    d = fm("metadata:\n  version: 1.2\n  author: 'J, D'\n").data
    assert d["metadata"] == {"version": "1.2", "author": "J, D"}


def test_split_is_backward_compatible():
    d, body = F.split("---\nname: x\n---\nb")
    assert d == {"name": "x"} and body == "b"


if __name__ == "__main__":
    n = 0
    for k, fn in list(globals().items()):
        if k.startswith("test_"):
            fn(); n += 1
    print(f"all {n} frontmatter tests passed")
