"""Context classification: is a span DIRECTIVE text or an EXAMPLE?

Defensive skills legitimately quote attack strings ("ignore previous
instructions") inside code fences, inline code, quotation marks, blockquotes
and tables. Those are *examples being discussed*, not instructions to the
model. We locate those spans so detectors can down-weight matches in them.

Security caveat (deliberate design choice): text inside a code fence is still
loaded into the model's context, and an attacker can fence a payload to try to
dodge detection. So example-context hits are DOWN-weighted, never ignored:
several fenced injection patterns still add up to REVIEW, and hidden-channel
rules are unaffected. See tests/corpus/malicious/fenced-evasion.
"""
from __future__ import annotations
import bisect
import re

_FENCE_RE = re.compile(r"^(```|~~~)[^\n]*\n.*?^\1[ \t]*$", re.DOTALL | re.MULTILINE)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_QUOTE_RE = re.compile(r'"[^"\n]{3,200}"|\u201c[^\u201d\n]{3,200}\u201d|\u300c[^\u300d\n]{2,200}\u300d')
_BLOCKQUOTE_RE = re.compile(r"^[ \t]*>.*$", re.MULTILINE)
_TABLE_ROW_RE = re.compile(r"^[ \t]*\|.*\|[ \t]*$", re.MULTILINE)

EXAMPLE_MULTIPLIER = 0.35


class Context:
    """Answers `is_example(pos)` in O(log n) over merged example spans."""

    def __init__(self, text: str):
        spans: list[tuple[int, int, str]] = []
        for m in _FENCE_RE.finditer(text):
            spans.append((m.start(), m.end(), "code_fence"))
        # NOTE: an UNCLOSED trailing fence is deliberately NOT treated as an
        # example. Otherwise a single leading ``` would down-weight the whole
        # file. Unbalanced fences are a mild evasion signal (see scoring).
        for rx, kind in ((_INLINE_CODE_RE, "inline_code"), (_QUOTE_RE, "quote"),
                         (_BLOCKQUOTE_RE, "blockquote"), (_TABLE_ROW_RE, "table")):
            for m in rx.finditer(text):
                spans.append((m.start(), m.end(), kind))
        spans.sort()
        self._starts = [s for s, _, _ in spans]
        self._spans = spans

    def kind_at(self, pos: int) -> str | None:
        i = bisect.bisect_right(self._starts, pos)
        # Check a few spans back (spans can overlap / nest).
        for j in range(i - 1, max(-1, i - 25), -1):
            s, e, kind = self._spans[j]
            if s <= pos < e:
                return kind
        return None

    def is_example(self, pos: int) -> bool:
        return self.kind_at(pos) is not None
