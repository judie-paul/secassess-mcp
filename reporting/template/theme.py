"""Colours, fonts and drawing helpers shared by every slide.

Change the look of the whole deck here; build_pptx.py never hard-codes a colour.
"""

from __future__ import annotations

from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)
MARGIN = 0.6  # inches
CONTENT_W = 13.333 - 2 * MARGIN

HEAD_FONT = "Cambria"
BODY_FONT = "Calibri"

COLORS = {
    "ink": "0F1B2D",        # dark slides, headings
    "ink2": "24364F",
    "text": "1B2430",
    "muted": "5B6675",
    "faint": "8A94A3",
    "line": "D9DEE5",
    "bg": "FFFFFF",
    "tint": "F3F5F8",
    "tint2": "E7ECF2",
    "accent": "0E7C86",     # teal: non-status highlights
    "accent_soft": "DCEFF1",
    "white": "FFFFFF",
    "on_dark_muted": "A9B4C4",
}

# Status colours are reserved for severity and always shown with a text label.
SEVERITY = {"critical": "B42318", "high": "D9480F", "medium": "B7791F", "low": "64748B"}
SEVERITY_SOFT = {"critical": "FDE8E6", "high": "FFEEE3", "medium": "FBF1DC", "low": "EEF1F5"}

SOURCE_LABELS = {
    "findings": "Configuration finding",
    "data_inventory": "Data inventory",
    "auth_logs": "Authentication logs",
}


def rgb(hex_value: str) -> RGBColor:
    return RGBColor.from_string(hex_value)


def set_background(slide, hex_value: str) -> None:
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = rgb(hex_value)


def add_box(slide, x, y, w, h, fill=None, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
            radius=0.06, name=None):
    shp = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        # radius is a fraction of the shorter side; keep corners similar across sizes
        shp.adjustments[0] = min(0.5, radius / min(w, h))
    if fill:
        shp.fill.solid()
        shp.fill.fore_color.rgb = rgb(fill)
    else:
        shp.fill.background()
    if line:
        shp.line.color.rgb = rgb(line)
        shp.line.width = Pt(0.75)
    else:
        shp.line.fill.background()
    shp.shadow.inherit = False
    # Drop the theme style reference: fill, line and text colours are all set
    # explicitly, and without this LibreOffice still draws the theme's shadow.
    style = shp._element.find(qn("p:style"))
    if style is not None:
        shp._element.remove(style)
    if name:
        shp.name = name
    return shp


def _style_run(run, size, color, bold=False, italic=False, font=BODY_FONT):
    f = run.font
    f.size = Pt(size)
    f.bold = bold
    f.italic = italic
    f.name = font
    f.color.rgb = rgb(color)


def add_text(slide, x, y, w, h, text, size=14, color=None, bold=False, italic=False,
             font=BODY_FONT, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, name=None,
             margin=0.0, line_spacing=None, shrink=False):
    """Add a text box. `text` is a string or a list of paragraphs, where each
    paragraph is a string or a list of (text, overrides) runs."""
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    if name:
        box.name = name
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    m = Inches(margin)
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = m
    tf.auto_size = MSO_AUTO_SIZE.TEXT_TO_FIT_SHAPE if shrink else MSO_AUTO_SIZE.NONE

    paragraphs = text if isinstance(text, list) else [text]
    color = color or COLORS["text"]
    for i, para in enumerate(paragraphs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        if line_spacing:
            p.line_spacing = line_spacing
        runs = para if isinstance(para, list) else [(para, {})]
        for run_text, opts in runs:
            r = p.add_run()
            r.text = run_text
            _style_run(r, opts.get("size", size), opts.get("color", color),
                       opts.get("bold", bold), opts.get("italic", italic), opts.get("font", font))
    return box


def add_bullets(slide, x, y, w, h, items, size=14, color=None, space_after=8, name=None):
    box = add_text(slide, x, y, w, h, items, size=size, color=color, name=name)
    for p in box.text_frame.paragraphs:
        p.space_after = Pt(space_after)
        pPr = p._p.get_or_add_pPr()
        pPr.set("marL", str(Inches(0.22)))
        pPr.set("indent", str(-Inches(0.22)))
        bu_clr = pPr.makeelement(qn("a:buClr"), {})
        srgb = bu_clr.makeelement(qn("a:srgbClr"), {"val": COLORS["accent"]})
        bu_clr.append(srgb)
        pPr.append(bu_clr)
        pPr.append(pPr.makeelement(qn("a:buChar"), {"char": "•"}))
    return box


def add_pill(slide, x, y, text, fill, color="FFFFFF", size=10, w=None, name=None):
    """Small rounded label, e.g. a severity tag. Width is estimated from the text."""
    w = w or max(0.6, 0.075 * len(text) * size / 10 + 0.3)
    h = 0.28 * size / 10
    box = add_box(slide, x, y, w, h, fill=fill, radius=h / 2, name=name)
    tf = box.text_frame
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = Emu(0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = text
    _style_run(r, size, color, bold=True)
    return box, w


def add_number_badge(slide, x, y, number, d=0.42, fill=None, color="FFFFFF", size=14):
    circ = add_box(slide, x, y, d, d, fill=fill or COLORS["accent"], shape=MSO_SHAPE.OVAL)
    tf = circ.text_frame
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Emu(0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = str(number)
    _style_run(r, size, color, bold=True)
    return circ


def add_title(slide, title, kicker=None, dark=False):
    """Same position, font and size on every content slide."""
    if kicker:
        add_text(slide, MARGIN, 0.42, CONTENT_W, 0.3, kicker.upper(), size=11, bold=True,
                 color=COLORS["accent"] if not dark else COLORS["on_dark_muted"], name="kicker")
    add_text(slide, MARGIN, 0.72, CONTENT_W, 0.75, title, size=30, bold=True, font=HEAD_FONT,
             color=COLORS["white"] if dark else COLORS["ink"], anchor=MSO_ANCHOR.TOP, name="title")


def add_footer(slide, left_text, page, dark=False):
    color = COLORS["on_dark_muted"] if dark else COLORS["faint"]
    add_text(slide, MARGIN, 7.0, 9.0, 0.25, left_text, size=10, color=color, name="chrome_footer")
    add_text(slide, 13.333 - MARGIN - 1.0, 7.0, 1.0, 0.25, str(page), size=10, color=color,
             align=PP_ALIGN.RIGHT, name="chrome_page")


def style_table(table, header_fill=None, size=12, col_align=None):
    header_fill = header_fill or COLORS["ink"]
    for r_idx, row in enumerate(table.rows):
        for c_idx, cell in enumerate(row.cells):
            cell.fill.solid()
            if r_idx == 0:
                cell.fill.fore_color.rgb = rgb(header_fill)
            else:
                cell.fill.fore_color.rgb = rgb(COLORS["white"] if r_idx % 2 else COLORS["tint"])
            cell.margin_left = cell.margin_right = Inches(0.1)
            cell.margin_top = cell.margin_bottom = Inches(0.05)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            for p in cell.text_frame.paragraphs:
                if col_align and c_idx in col_align:
                    p.alignment = col_align[c_idx]
                for run in p.runs:
                    _style_run(run, size, COLORS["white"] if r_idx == 0 else COLORS["text"],
                               bold=(r_idx == 0))
