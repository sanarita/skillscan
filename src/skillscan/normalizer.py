"""Text normalization and safe decoding helpers (stdlib only).

The scanner treats every input as untrusted DATA. Nothing here ever
executes or evaluates content; we only inspect and decode it.
"""
from __future__ import annotations
import base64
import binascii
import re
import unicodedata

# Zero-width / invisible formatting characters often used to smuggle text.
ZERO_WIDTH = {
    "\u200b", "\u200c", "\u2060", "\ufeff",
    "\u180e", "\u00ad",
}
# Bidirectional / directional overrides (Trojan-Source style).
BIDI_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

_CONFUSABLE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}\s*){20,}")


# 1:1 character folding applied before rule matching. Length-preserving on
# purpose: detectors map match offsets back to Context (code fence / quote
# spans) computed on the original text, so no character may be added/removed.
#   - typographic apostrophes/quotes (Word autocorrect: Don\u2019t) -> ASCII
#   - exotic spaces (NBSP, en/em/thin, ideographic) -> ' '
_MATCH_FOLD = str.maketrans({
    **{c: "'" for c in "\u2018\u2019\u201a\u201b\u2032\u02bc\uff07"},
    **{c: '"' for c in "\u201c\u201d\u201e\u201f\u2033\uff02"},
    **{c: " " for c in "\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
                        "\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"},
})


def fold_for_match(text: str) -> str:
    """Length-preserving normalization for rule matching (see _MATCH_FOLD)."""
    return text.translate(_MATCH_FOLD)


def strip_invisibles(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH and ch not in BIDI_CONTROLS)


def has_invisibles(text: str) -> bool:
    return any(ch in ZERO_WIDTH or ch in BIDI_CONTROLS for ch in text)


def suspicious_confusables(text: str) -> list[str]:
    """Return ASCII-looking words that actually contain non-Latin letters
    (a cheap homoglyph heuristic, e.g. Cyrillic 'а' inside an English word)."""
    hits = []
    for word in re.findall(r"\w{2,}", text):
        scripts = set()
        for ch in word:
            if ch.isalpha():
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    continue
                scripts.add(name.split(" ")[0])
        # Only Latin mixed with a look-alike script is a homoglyph risk;
        # Latin + CJK/HIRAGANA/KATAKANA (normal Japanese) is not.
        if "LATIN" in scripts and scripts & _CONFUSABLE_SCRIPTS:
            hits.append(word)
    return hits


def suspicious_confusables_with_pos(text: str) -> list[tuple[str, int]]:
    """Like suspicious_confusables, but returns (word, offset) pairs."""
    bad = set(suspicious_confusables(text))
    return [(m.group(0), m.start()) for m in re.finditer(r"\w{2,}", text) if m.group(0) in bad]


def _looks_texty(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in s)
    if s and printable / len(s) > 0.85:
        return s
    return None


def decode_blobs(text: str) -> list[dict]:
    """Find base64/hex blobs and, if they decode to readable text, surface it.
    Never executes; only decodes for inspection."""
    found = []
    for m in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0), validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _looks_texty(decoded)
        if s:
            found.append({"kind": "base64", "decoded": s, "pos": m.start()})
    for m in _HEX_RE.finditer(text):
        hexstr = re.sub(r"\s+", "", m.group(0))
        if len(hexstr) % 2:
            continue
        try:
            decoded = bytes.fromhex(hexstr)
        except ValueError:
            continue
        s = _looks_texty(decoded)
        if s:
            found.append({"kind": "hex", "decoded": s, "pos": m.start()})
    return found
