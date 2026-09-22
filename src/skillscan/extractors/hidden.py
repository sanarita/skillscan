"""Hidden-region extraction (v0.2: position-aware, no double counting).

Each Region carries `pos` (offset in the body) so detectors can ask the
Context whether the region sits inside an example (code fence, quote...).

v0.2 changes vs v0.1:
- The `visible` region has HTML comments blanked out (same length, so offsets
  stay valid). A directive hidden in a comment is scored once, as hidden.
- The `invisible` region is only the LINES that contain zero-width/bidi
  characters, not a copy of the whole document.

Seam for IPI Guard: swap `extract_regions()`; keep the Region shape.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from .. import normalizer

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


@dataclass
class Region:
    kind: str            # visible | html_comment | invisible | base64 | hex | confusable
    text: str
    pos: int = 0         # offset of the region in the body (for context lookup)
    note: str = ""
    meta: dict = field(default_factory=dict)


REGION_MULTIPLIER = {
    "visible": 1.0,
    "frontmatter": 1.2,
    "confusable": 1.5,
    "html_comment": 1.6,
    "base64": 2.0,
    "hex": 2.0,
    "invisible": 2.2,
}
# Channels a human reviewer would not read at a glance. Frontmatter is
# high-value but VISIBLE, so it is deliberately excluded here.
HIDDEN_KINDS = {"confusable", "html_comment", "base64", "hex", "invisible"}


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    chars = list(text)
    for s, e in spans:
        for i in range(s, e):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def extract_regions(text: str) -> list[Region]:
    regions: list[Region] = []

    comment_spans = []
    for m in _HTML_COMMENT_RE.finditer(text):
        comment_spans.append((m.start(), m.end()))
        body = m.group(1).strip()
        if body:
            regions.append(Region("html_comment", body, pos=m.start(),
                                  note="text inside an HTML comment"))

    regions.insert(0, Region("visible", _blank(text, comment_spans), pos=0))

    offset = 0
    for line in text.splitlines(keepends=True):
        if normalizer.has_invisibles(line):
            regions.append(Region("invisible", normalizer.strip_invisibles(line), pos=offset,
                                  note="zero-width / bidi control characters in line"))
        offset += len(line)

    for word, pos in normalizer.suspicious_confusables_with_pos(text):
        regions.append(Region("confusable", word, pos=pos, note="mixed-script (homoglyph) word"))

    for blob in normalizer.decode_blobs(text):
        regions.append(Region(blob["kind"], blob["decoded"], pos=blob["pos"],
                              note=f"decoded {blob['kind']} blob"))
    return regions
