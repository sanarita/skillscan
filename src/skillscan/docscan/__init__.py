"""docscan: indirect-prompt-injection scanner for PDF / DOCX files.

Scope, deliberately narrow: this checks whether a document's extracted text
contains instructions directed at an LLM reader (the "indirect prompt
injection" pattern skillscan already detects in SKILL.md files) -- NOT
whether the file is a malicious PDF/DOCX in the traditional sense.

Out of scope, by design (use dedicated tools for these instead):
  - VBA/Office macros            -> oletools (olevba)
  - Embedded PDF JavaScript/OpenAction/EmbeddedFile -> pdfid / pdf-parser
  - Parser exploits / malformed-file attacks         -> sandboxed detonation

Reuses skillscan's injection rule pack (`rules/injection.json`) and its
context-aware scoring philosophy (region multiplier x context multiplier),
so the two tools share one vocabulary of finding ids and one set of regexes
to maintain.

Why "hidden regions" matter more here than in SKILL.md: a human skimming a
Word/PDF document will not see white-on-white text, a font sized at 1pt, a
Word "hidden" run, a tracked-change insertion, or a document-property field
-- but a naive "extract all text and read it" pipeline will. Each of those
becomes its own Region so it gets the hidden-channel weight.
"""
from __future__ import annotations
