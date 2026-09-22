"""Fail-closed SKILL.md frontmatter parser (v0.4).

Why not a YAML library?  Two reasons, stated honestly:
  1. skillscan is stdlib-only by design (no dependencies in CI hooks).
  2. `yaml.safe_load` does NOT execute code, but swapping parsers would not
     remove the real risk for a *scanner*: a **parser differential**. If this
     parser reads something different from what the skill loader reads, an
     attacker hides a payload in the gap.

So this parser is built to be *fail-closed* rather than "complete":
  - every line lands somewhere (a value, or `gaps`) - nothing is silently dropped;
  - YAML features a scanner should not have to resolve (anchors, aliases, tags,
    flow mappings, character-code escapes, invisible characters, duplicate or
    quoted keys) are recorded as `anomalies` and surfaced as findings;
  - the raw frontmatter text is kept so callers can scan it as defence in depth.

Parsing is linear in the input size and never expands aliases (no billion-laughs).
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass, field
from enum import IntEnum

_FM_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)^---[ \t]*\r?$\n?", re.DOTALL | re.MULTILINE)
_KEY_RE = re.compile(
    r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\-\[\]{}][^:]*?|-[^\s:][^:]*?)"""
    r"""[ \t]*:(?:[ \t]+(?P<rest>.*)|[ \t]*$)""")
_BLOCK_RE = re.compile(r"^(?P<style>[|>])(?:[+-]?[1-9]?|[1-9][+-])[ \t]*(?:#.*)?$")
_INVISIBLE_RE = re.compile(
    "[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_ESC_RE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", re.DOTALL)
_ESC_SIMPLE = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n",
               "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"',
               "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
_MAX_DEPTH = 4

# Keys whose values decide when a skill auto-loads.
TRIGGER_KEYS = ("name", "description", "triggers", "trigger", "when_to_use", "when-to-use")


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Frontmatter:
    data: dict = field(default_factory=dict)
    body: str = ""
    raw: str = ""
    present: bool = False
    gaps: list[str] = field(default_factory=list)            # lines not understood
    anomalies: list[tuple[str, str]] = field(default_factory=list)   # (kind, evidence)

    def note(self, kind: str, evidence: str) -> None:
        self.anomalies.append((kind, " ".join(evidence.split())[:80]))


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def parse(text: str) -> Frontmatter:
    """Split and parse. Tolerates a UTF-8 BOM and CRLF line endings."""
    if text.startswith("\ufeff"):
        text = text[1:]
    m = _FM_RE.match(text)
    if not m:
        return Frontmatter(body=text)
    fm = Frontmatter(body=text[m.end():], raw=m.group(1), present=True)
    if _INVISIBLE_RE.search(fm.raw):
        fm.note("invisible_chars", repr(_INVISIBLE_RE.search(fm.raw).group(0)))
    fm.data = _parse_mapping(fm.raw.splitlines(), fm, depth=0)
    return fm


def split(text: str) -> tuple[dict, str]:
    """Backward-compatible v0.3 API: (frontmatter_dict, body)."""
    fm = parse(text)
    return fm.data, fm.body


def normalize(s: str) -> str:
    """NFKC (full-width -> ASCII) and strip invisible/bidi characters."""
    return _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", s))


def flatten(obj) -> list[str]:
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in flatten(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in flatten(v)]
    return [] if obj is None else [str(obj)]


def scan_text(fm: Frontmatter) -> str:
    """Everything an injection detector should see: decoded values first
    (so directives win over quoted raw copies), then gaps, then the raw text."""
    parts = flatten(fm.data) + fm.gaps + [fm.raw]
    return normalize("\n".join(p for p in parts if p))


# --------------------------------------------------------------------------- #
# line parser
# --------------------------------------------------------------------------- #
def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _dedent(lines: list[str]) -> list[str]:
    ind = min((_indent(l) for l in lines if l.strip()), default=0)
    return [l[ind:] if l.strip() else "" for l in lines]


def _parse_mapping(lines: list[str], fm: Frontmatter, depth: int) -> dict:
    data: dict = {}
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = _KEY_RE.match(line)
        if not m or line[0] in " \t":
            fm.gaps.append(line.strip())
            i += 1
            continue
        key_tok, rest = m.group("key"), (m.group("rest") or "")
        key = _decode_key(key_tok, fm)
        if key in data:
            fm.note("duplicate_key", key)
        j = i + 1
        while j < n and (not lines[j].strip() or lines[j][0] in " \t"
                         or (not rest.strip() and lines[j].startswith("-"))):
            j += 1
        children = lines[i + 1:j]
        while children and not children[-1].strip():
            children.pop()
        data[key] = _value(rest, children, fm, depth)
        i = j
    return data


def _decode_key(tok: str, fm: Frontmatter) -> str:
    if tok[:1] in "\"'":
        fm.note("quoted_key", tok)
        return _dquote(tok[1:-1], fm) if tok[0] == '"' else tok[1:-1].replace("''", "'")
    return tok.strip()


def _strip_comment(s: str) -> str:
    """Remove a trailing ` # comment` from a PLAIN scalar (YAML needs a space)."""
    if s.startswith("#"):
        return ""
    return re.split(r"[ \t]#", s, maxsplit=1)[0].rstrip()


def _value(rest: str, children: list[str], fm: Frontmatter, depth: int):
    rest = rest.strip()
    # Node properties a scanner should never have to resolve.
    while rest[:1] in ("&", "!"):
        tok, _, rest = rest.partition(" ")
        fm.note("anchor" if tok[0] == "&" else "tag", tok)
        rest = rest.strip()
    if rest.startswith("*"):
        fm.note("alias", rest)
        return _strip_comment(rest)

    if not rest or rest.startswith("#"):
        body = [c for c in children if c.strip()]
        if not body:
            return ""
        if depth >= _MAX_DEPTH:
            fm.note("deep_nesting", body[0])
            return " ".join(c.strip() for c in body)
        ded = _dedent(children)
        if ded[0].startswith("-") or next(l for l in ded if l).startswith("-"):
            return _block_list(ded, fm, depth)
        return _parse_mapping(ded, fm, depth + 1)

    bm = _BLOCK_RE.match(rest)
    if bm:
        content = _dedent(children)       # keeps '#', ':' and '-' lines verbatim
        if bm.group("style") == "|":
            return "\n".join(content).strip("\n")
        return " ".join(l.strip() for l in content if l.strip())

    if rest[0] in "\"'":
        return _quoted(rest, children, fm)
    if rest[0] == "[":
        return _flow_list(rest, children, fm)
    if rest[0] == "{":
        fm.note("flow_mapping", rest)
        return " ".join([rest] + [c.strip() for c in children])

    # plain scalar, possibly continued on more-indented lines
    parts = [_strip_comment(rest)] + [_strip_comment(c.strip()) for c in children if c.strip()]
    return " ".join(p for p in parts if p)


def _block_list(lines: list[str], fm: Frontmatter, depth: int) -> list:
    items: list = []
    cur: list[str] | None = None
    for l in lines:
        if not l.strip():
            continue
        if l.startswith("-") and (len(l) == 1 or l[1] in " \t"):
            if cur is not None:
                items.append(_item(cur, fm, depth))
            cur = [l[1:].strip()]
        elif cur is not None:
            cur.append(l.strip())           # continuation / nested content
        else:
            fm.gaps.append(l.strip())
    if cur is not None:
        items.append(_item(cur, fm, depth))
    return items


def _item(parts: list[str], fm: Frontmatter, depth: int):
    head, tail = parts[0], parts[1:]
    if head[:1] in "\"'":
        return _quoted(head, tail, fm)
    if head[:1] in "&!*{" or head.startswith("["):
        return _value(head, ["  " + t for t in tail], fm, depth + 1)
    return " ".join(p for p in [_strip_comment(head)] + tail if p)


def _quoted(rest: str, children: list[str], fm: Frontmatter) -> str:
    q = rest[0]
    s = " ".join([rest] + [c.strip() for c in children if c.strip()])
    i = 1
    while i < len(s):
        if q == '"' and s[i] == "\\":
            i += 2
            continue
        if s[i] == q:
            if q == "'" and s[i + 1:i + 2] == "'":
                i += 2
                continue
            break
        i += 1
    inner, trailing = s[1:i], s[i + 1:].strip()
    if i >= len(s):
        fm.note("unterminated_quote", rest)
    elif trailing and not trailing.startswith("#"):
        fm.gaps.append(trailing)
    return _dquote(inner, fm) if q == '"' else inner.replace("''", "'")


def _dquote(s: str, fm: Frontmatter) -> str:
    def rep(m: re.Match) -> str:
        e = m.group(1)
        if e[0] in "xuU" and len(e) > 1:
            fm.note("escape_sequence", "\\" + e)
            try:
                return chr(int(e[1:], 16))
            except (ValueError, OverflowError):
                return ""
        return _ESC_SIMPLE.get(e, e)
    return _ESC_RE.sub(rep, s)


def _flow_list(rest: str, children: list[str], fm: Frontmatter):
    s = " ".join([rest] + [c.strip() for c in children if c.strip()])
    items, buf, q, depth, end = [], [], None, 0, None
    for idx, ch in enumerate(s[1:], start=1):
        if q:
            buf.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}" and depth:
            depth -= 1
            buf.append(ch)
        elif ch == "]":
            end = idx
            break
        elif ch == ",":
            items.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    items.append("".join(buf))
    if end is None:
        fm.note("unterminated_flow", rest)
    elif s[end + 1:].strip() and not s[end + 1:].strip().startswith("#"):
        fm.gaps.append(s[end + 1:].strip())
    out = []
    for it in (x.strip() for x in items):
        if not it:
            continue
        if it[0] in "[{":
            fm.note("flow_nested", it)
            out.append(it)
        elif it[0] in "\"'":
            out.append(_quoted(it, [], fm))
        else:
            out.append(it)
    return out


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #
_NARROWING = r"(?!\s+(?:involving|related|about|that|which|with|regarding|where|using|containing|of)\b)"
_EN_NOUNS = (r"(?:requests?|messages?|conversations?|inputs?|turns?|tasks?|prompts?|"
             r"quer(?:y|ies)|questions?|interactions?|chats?|topics?)")
_BROAD_PATTERNS = [
    ("always_load", re.compile(
        r"\b(?:always|automatically|unconditionally)\s+(?:be\s+)?"
        r"(?:load|use|apply|activat|trigger|run|invok|includ|enabl)\w*", re.I)),
    ("any_input", re.compile(rf"\b(?:any|every|all|each)\s+{_EN_NOUNS}\b{_NARROWING}", re.I)),
    ("regardless", re.compile(
        r"\b(?:regardless of|no matter)\s+(?:what|the\s+(?:request|task|topic|context|input|query))\b",
        re.I)),
    ("whenever_anything", re.compile(
        r"\b(?:whenever|any ?time)\b[^.\n]{0,30}\b(?:anything|something)\b", re.I)),
    ("wildcard", re.compile(r"(?:^|[\s,\[(\"'|])\*(?=$|[\s,\])\"'|])")),
    ("ja_always_load", re.compile(
        r"(?:常に|必ず|毎回|自動的?に|無条件に)[^。\n]{0,10}"
        r"(?:読み込|ロード|使用|使[うっい]|適用|起動|有効|発動|呼び出)")),
    ("ja_any_input", re.compile(
        r"(?:すべて|全て|あらゆる|全部)の(?:会話|依頼|リクエスト|メッセージ|入力|質問|タスク|やり取り|プロンプト)")),
    ("ja_whatever", re.compile(
        r"(?:どんな|いかなる|どの)(?:会話|依頼|リクエスト|メッセージ|入力|質問|タスク)"
        r"(?:でも|に対しても|であっても|にも)|(?:内容|話題|トピック|依頼)に(?:関係なく|かかわらず|関わらず)")),
]

# anomaly kind -> (finding id, severity)
_ANOMALY_FINDING = {
    "alias": ("fm_obfuscation", Severity.HIGH),
    "anchor": ("fm_obfuscation", Severity.HIGH),
    "tag": ("fm_obfuscation", Severity.HIGH),
    "flow_mapping": ("fm_obfuscation", Severity.HIGH),
    "flow_nested": ("fm_obfuscation", Severity.MEDIUM),
    "invisible_chars": ("fm_obfuscation", Severity.HIGH),
    "duplicate_key": ("fm_duplicate_key", Severity.HIGH),
    "escape_sequence": ("fm_escape", Severity.LOW),
    "quoted_key": ("fm_quoted_key", Severity.LOW),
    "deep_nesting": ("fm_parse_gap", Severity.HIGH),
    "unterminated_quote": ("fm_parse_gap", Severity.HIGH),
    "unterminated_flow": ("fm_parse_gap", Severity.HIGH),
}


def _finding(fid: str, sev: Severity, detail: str, key: str = "", evidence: str = "") -> dict:
    return {"id": fid, "severity": int(sev), "detail": detail, "key": key,
            "evidence": " ".join(evidence.split())[:80]}


def analyze_triggers(fm: dict, extra_text: str = "") -> list[dict]:
    """Flag frontmatter that would cause overly broad auto-loading.
    Keys are matched case-insensitively; values are NFKC-normalized first."""
    fields = {normalize(str(k)).strip().lower(): v for k, v in fm.items()}
    sources = [(k, " | ".join(flatten(fields.get(k)))) for k in TRIGGER_KEYS if k in fields]
    if extra_text:
        sources.append(("(unparsed)", extra_text))
    for key, text in sources:
        text = normalize(text)
        for pid, rx in _BROAD_PATTERNS:
            m = rx.search(text)
            if m:
                return [_finding("broad_autoload", Severity.MEDIUM,
                                 f"frontmatter would auto-load this skill for almost any input ({pid})",
                                 key, m.group(0).strip())]
    return []


def analyze(fm: Frontmatter) -> list[dict]:
    """All frontmatter findings: broad triggers, parse gaps, obfuscation."""
    findings = analyze_triggers(fm.data, "\n".join(fm.gaps))
    if fm.gaps:
        findings.append(_finding(
            "fm_parse_gap", Severity.HIGH,
            f"{len(fm.gaps)} frontmatter line(s) could not be parsed; a real YAML loader "
            f"may read them differently (fail-closed)", evidence=fm.gaps[0]))
    seen: set[str] = set()
    for kind, ev in fm.anomalies:
        fid, sev = _ANOMALY_FINDING.get(kind, ("fm_obfuscation", Severity.MEDIUM))
        if fid in seen:
            continue
        seen.add(fid)
        findings.append(_finding(fid, sev, f"frontmatter uses {kind.replace('_', ' ')}",
                                 evidence=ev))
    return findings
