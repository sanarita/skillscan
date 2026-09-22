"""PDF text extraction, split into regions by visibility to a human reader
who opens the file at a normal zoom level and does not open the layers/
attachments panes.

Region kinds produced:
  visible        - normal, rendered, readable text
  invisible_mode - text painted with PDF text-rendering mode 3 (neither
                   fill nor stroke) -- literally invisible. This mode is
                   also legitimately used for OCR text layers over a scanned
                   image, so it is a signal, not proof; scoring treats it as
                   a hidden channel regardless, same as skillscan's stance
                   on other hidden channels.
  tiny_font      - text sized <= TINY_PT
  white_on_white - fill color is pure/near-white with no evidence of a
                   contrasting background (best-effort; PDF has no simple
                   "background color" concept, so this is conservative and
                   under-detects by design rather than over-flagging)
  annotation     - a comment/sticky-note/free-text annotation; not part of
                   the page content stream, invisible unless the comments
                   pane is opened
  doc_property   - document Info dictionary fields (Title, Subject, Keywords,
                   Author, Producer, Creator) and XMP metadata; never
                   rendered on any page

Out of scope here: embedded JavaScript, /OpenAction, /EmbeddedFile, optional
content groups (layers) used to hide content in ways a renderer respects --
those are attack surfaces of a different KIND (executable/structural, not
"text a human won't read") and belong to a PDF-structure scanner, not this
one. See docscan/__init__.py for the boundary.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams, LTChar, LTPage, LTTextContainer
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser

TINY_PT = 4.0
_NEAR_WHITE = 0.92   # average RGB channel value above this = "white-ish"


class _RenderModeAggregator(PDFPageAggregator):
    """pdfminer.six threads the text-rendering mode (Tr, e.g. mode 3 =
    invisible) through PDFTextState but drops it before LTChar is built --
    render_char() never receives it. We capture it in render_string() (the
    one call site that still has textstate) and tag every LTChar this page
    produces, so _classify_char() can see it. See PDF Reference 9.3.3."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._render_mode = 0

    def render_string(self, textstate, seq, ncs, graphicstate):
        self._render_mode = textstate.render
        return super().render_string(textstate, seq, ncs, graphicstate)

    def render_char(self, matrix, font, fontsize, scaling, rise, cid, ncs, graphicstate):
        width = super().render_char(matrix, font, fontsize, scaling, rise, cid, ncs, graphicstate)
        last = self.cur_item._objs[-1] if self.cur_item._objs else None
        if isinstance(last, LTChar):
            last.rendermode = self._render_mode
        return width


def _extract_pages(path):
    with open(path, "rb") as f:
        rsrcmgr = PDFResourceManager()
        device = _RenderModeAggregator(rsrcmgr, laparams=LAParams())
        interp = PDFPageInterpreter(rsrcmgr, device)
        for page in PDFPage.get_pages(f):
            interp.process_page(page)
            layout = device.get_result()
            yield layout


@dataclass
class Region:
    kind: str
    text: str
    note: str = ""
    meta: dict = field(default_factory=dict)


def _fill_rgb(gs) -> tuple[float, float, float] | None:
    """Best-effort: pdfminer exposes the fill color as whatever the color
    space returns (often a tuple of 0-1 floats for RGB/Gray/CMYK). Only RGB
    and Gray are interpreted; CMYK/ICC/Separation are left alone (returns
    None) rather than guessed at, matching this module's conservative bias."""
    color = getattr(gs, "ncolor", None)
    if color is None:
        return None
    if isinstance(color, (int, float)):
        return (color, color, color)
    if isinstance(color, tuple) and len(color) == 3:
        return color
    return None


def _classify_char(ch: LTChar) -> str:
    if getattr(ch, "rendermode", 0) == 3:
        return "invisible_mode"
    if ch.size <= TINY_PT:
        return "tiny_font"
    rgb = _fill_rgb(ch.graphicstate)
    if rgb is not None and min(rgb) >= _NEAR_WHITE:
        return "white_on_white"
    return "visible"


def _page_regions(layout) -> list[Region]:
    buf: dict[str, list[str]] = {}
    for element in layout:
        if not isinstance(element, LTTextContainer):
            continue
        for line in element:
            if not hasattr(line, "__iter__"):
                continue
            run_kind, run_chars = None, []
            for ch in line:
                if not isinstance(ch, LTChar):
                    continue
                kind = _classify_char(ch)
                if kind != run_kind and run_chars:
                    buf.setdefault(run_kind, []).append("".join(run_chars))
                    run_chars = []
                run_kind = kind
                run_chars.append(ch.get_text())
            if run_chars:
                buf.setdefault(run_kind, []).append("".join(run_chars))
    notes = {
        "invisible_mode": "text-rendering mode 3 (invisible; also used for OCR layers)",
        "tiny_font": f"font size <= {TINY_PT:g}pt, unreadable at normal zoom",
        "white_on_white": "near-white fill color, no detected contrasting background",
        "visible": "",
    }
    return [Region(kind, "".join(parts), note=notes.get(kind, ""))
            for kind, parts in buf.items() if "".join(parts).strip()]


def _annotations(path) -> list[Region]:
    regions: list[Region] = []
    try:
        from pypdf import PdfReader
    except ImportError:
        return regions
    try:
        reader = PdfReader(str(path))
    except Exception:
        return regions
    for page in reader.pages:
        for annot in page.get("/Annots") or []:
            obj = annot.get_object()
            contents = obj.get("/Contents")
            if contents:
                subtype = str(obj.get("/Subtype", "?")).lstrip("/")
                regions.append(Region("annotation", str(contents),
                                      note=f"PDF {subtype} annotation"))
    info = reader.metadata or {}
    for key in ("/Title", "/Subject", "/Keywords", "/Author", "/Producer", "/Creator"):
        val = info.get(key)
        if val and str(val).strip():
            regions.append(Region("doc_property", str(val),
                                  note=f"document info field: {key.lstrip('/')}"))
    try:
        xmp = reader.xmp_metadata
        if xmp is not None:
            for attr in ("dc_title", "dc_description", "dc_subject"):
                val = getattr(xmp, attr, None)
                text = " ".join(val) if isinstance(val, (list, tuple)) else val
                if text and str(text).strip():
                    regions.append(Region("doc_property", str(text), note=f"XMP {attr}"))
    except Exception:
        pass
    return regions


def extract(path) -> list[Region]:
    regions: list[Region] = []
    for layout in _extract_pages(str(path)):
        regions.extend(_page_regions(layout))
    regions.extend(_annotations(path))
    return regions
