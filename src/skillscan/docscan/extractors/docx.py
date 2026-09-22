"""DOCX text extraction, split into regions by how visible each part is to
a human reader who opens the file normally (no special view settings).

Region kinds produced:
  visible          - ordinary paragraph text, tables, headers/footers, footnotes
  hidden_run       - text with Word's "Hidden" character property (w:vanish);
                     invisible unless "Show hidden text" / formatting marks is on
  tiny_font        - text sized <= TINY_PT; readable only by zooming in hard
  white_on_white   - text color matches (or is very close to) the paragraph's
                     highlight/shading, or is pure white with no shading
  comment          - a Word comment/annotation; many reviewers never open the
                     comments pane, and a comment is never "on the page"
  tracked_insert   - a tracked-change insertion; invisible if changes are
                     "accepted" in the view, or if simple markup hides them
  doc_property     - core/custom/app document properties (Title, Subject,
                     Keywords, Comments, custom XML parts); never rendered
                     on the page at all
  alt_text         - image/shape alt-text (accessibility description);
                     invisible to a sighted reader, read by many automated
                     pipelines and screen readers
"""
from __future__ import annotations
import zipfile
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_CP = "{http://schemas.openxmlformats.org/package/2006/core-properties}"
_DC = "{http://purl.org/dc/elements/1.1/}"
_DCTERMS = "{http://purl.org/dc/terms/}"
_EP = "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_WP = "{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}"
_VT = "{http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes}"
_CUSTOM = "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}"

TINY_PT = 5.0            # <= 5pt is unreadable at normal zoom
_WHITE = {"FFFFFF", "FFF", "auto"}


@dataclass
class Region:
    kind: str
    text: str
    note: str = ""
    meta: dict = field(default_factory=dict)


def _rpr_hidden(rpr) -> bool:
    if rpr is None:
        return False
    v = rpr.find(_W + "vanish")
    return v is not None and v.get(_W + "val") not in ("0", "false")


def _rpr_size_pt(rpr):
    if rpr is None:
        return None
    sz = rpr.find(_W + "sz")
    if sz is None:
        sz = rpr.find(_W + "szCs")
    if sz is None:
        return None
    try:
        return int(sz.get(_W + "val")) / 2.0   # half-points -> points
    except (TypeError, ValueError):
        return None


def _rpr_white(rpr) -> bool:
    if rpr is None:
        return False
    color = rpr.find(_W + "color")
    hi = rpr.find(_W + "highlight")
    shd = rpr.find(_W + "shd")
    col_val = (color.get(_W + "val") if color is not None else "").upper()
    hi_val = (hi.get(_W + "val") if hi is not None else "").lower()
    fill = (shd.get(_W + "fill") if shd is not None else "").upper()
    if col_val not in _WHITE:
        return False
    # White text is invisible unless something is shading the paragraph.
    if hi_val and hi_val != "none":
        return False
    if fill and fill not in _WHITE and fill != "AUTO":
        return False
    return True


def _run_text(r) -> str:
    return "".join(t.text or "" for t in r.findall(_W + "t"))


def _walk_runs(container, kind_default: str, regions: list[Region]):
    """Emit one Region per run, splitting hidden/tiny/white-on-white out of
    the ordinary visible stream."""
    for r in container.iter(_W + "r"):
        text = _run_text(r)
        if not text.strip():
            continue
        rpr = r.find(_W + "rPr")
        if _rpr_hidden(rpr):
            regions.append(Region("hidden_run", text,
                                  note="Word 'hidden text' character property (w:vanish)"))
            continue
        size = _rpr_size_pt(rpr)
        if size is not None and size <= TINY_PT:
            regions.append(Region("tiny_font", text,
                                  note=f"font size {size:g}pt, unreadable at normal zoom"))
            continue
        if _rpr_white(rpr):
            regions.append(Region("white_on_white", text,
                                  note="text color white with no contrasting shading"))
            continue
        regions.append(Region(kind_default, text))


def _walk_tracked_inserts(root, regions: list[Region]):
    for ins in root.iter(_W + "ins"):
        text = "".join(_run_text(r) for r in ins.findall(_W + "r"))
        if text.strip():
            regions.append(Region("tracked_insert", text,
                                  note="tracked-change insertion (ins)"))


def _walk_alt_text(root, regions: list[Region]):
    for tag in (_WP + "docPr",):
        for el in root.iter(tag):
            desc = el.get("descr") or ""
            title = el.get("title") or ""
            for label, val in (("alt-text", desc), ("title", title)):
                if val.strip():
                    regions.append(Region("alt_text", val, note=f"image/shape {label}"))


def _read_part(z: zipfile.ZipFile, name: str):
    try:
        return ET.fromstring(z.read(name))
    except (KeyError, ET.ParseError):
        return None


def _core_properties(z: zipfile.ZipFile, regions: list[Region]):
    root = _read_part(z, "docProps/core.xml")
    if root is not None:
        for el in root:
            if el.text and el.text.strip():
                tag = el.tag.split("}")[-1]
                regions.append(Region("doc_property", el.text,
                                      note=f"core document property: {tag}"))
    root = _read_part(z, "docProps/app.xml")
    if root is not None:
        for tag in ("Company", "Manager", "HyperlinkBase"):
            el = root.find(_EP + tag)
            if el is not None and el.text and el.text.strip():
                regions.append(Region("doc_property", el.text,
                                      note=f"app document property: {tag}"))
    root = _read_part(z, "docProps/custom.xml")
    if root is not None:
        for prop in root.findall(_CUSTOM + "property"):
            for child in prop:
                if child.text and child.text.strip():
                    name = prop.get("name", "?")
                    regions.append(Region("doc_property", child.text,
                                          note=f"custom document property: {name}"))


def extract(path) -> list[Region]:
    """Returns Regions covering: body, tables, headers/footers, footnotes/
    endnotes, comments, tracked changes, alt-text, and document properties.
    Never executes macros; VBA (vbaProject.bin) is not inspected here."""
    regions: list[Region] = []
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())

        root = _read_part(z, "word/document.xml")
        if root is not None:
            _walk_runs(root, "visible", regions)
            _walk_tracked_inserts(root, regions)
            _walk_alt_text(root, regions)

        for name in names:
            if name.startswith("word/header") or name.startswith("word/footer"):
                r = _read_part(z, name)
                if r is not None:
                    _walk_runs(r, "visible", regions)
            elif name in ("word/footnotes.xml", "word/endnotes.xml"):
                r = _read_part(z, name)
                if r is not None:
                    _walk_runs(r, "visible", regions)
            elif name == "word/comments.xml":
                r = _read_part(z, name)
                if r is not None:
                    for c in r.findall(_W + "comment"):
                        text = " ".join(_run_text(x) for x in c.iter(_W + "r"))
                        if text.strip():
                            author = c.get(_W + "author", "?")
                            regions.append(Region("comment", text,
                                                  note=f"Word comment by {author}"))

        _core_properties(z, regions)
    return regions
