"""Heuristic shell tokenizer for install scripts.

We do not build a real shell AST — we split into inspectable command/pipeline
strings so the install detector can pattern-match. Nothing is executed.
"""
from __future__ import annotations
import re

_SPLIT_RE = re.compile(r"[\n;]+|&&|\|\|")


def _join_continuations(script: str) -> str:
    return script.replace("\\\n", " ")


def commands(script: str) -> list[str]:
    script = _join_continuations(script)
    out = []
    for raw in _SPLIT_RE.split(script):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def pipelines(script: str) -> list[str]:
    """Return whole logical lines that contain a pipe, so we can spot
    download|shell chains that a naive per-command split would break apart."""
    script = _join_continuations(script)
    out = []
    for raw in re.split(r"[\n;]+|&&|\|\|", script):
        line = raw.strip()
        if "|" in line and not line.startswith("#"):
            out.append(line)
    return out
