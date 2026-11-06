"""Native PowerPoint charts, so the client can click a chart and edit its data.

Chart values come straight from the contract JSON and are never rounded or
re-typed. The heatmap is drawn with shapes because PowerPoint has no native
heatmap chart.
"""

from __future__ import annotations

from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt

from .template.theme import BODY_FONT, COLORS, SEVERITY, SEVERITY_SOFT, add_box, add_text, rgb

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _quiet_chart(chart, horizontal: bool):
    chart.has_legend = False
    chart.has_title = False
    chart.font.name = BODY_FONT
    chart.font.size = Pt(12)
    chart.font.color.rgb = rgb(COLORS["muted"])

    va = chart.value_axis
    va.visible = False
    va.has_major_gridlines = False
    va.has_minor_gridlines = False

    ca = chart.category_axis
    ca.has_major_gridlines = False
    ca.tick_labels.font.size = Pt(12)
    ca.tick_labels.font.color.rgb = rgb(COLORS["text"])
    ca.format.line.color.rgb = rgb(COLORS["line"])
    if horizontal:
        ca.reverse_order = True  # first category at the top

    plot = chart.plots[0]
    plot.gap_width = 55
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.font.size = Pt(12)
    dl.font.bold = True
    dl.font.color.rgb = rgb(COLORS["text"])
    dl.number_format = "0"
    dl.number_format_is_linked = False
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    # Keep long figures such as 1,284,000 on one line.
    body_pr = dl._element.get_or_add_txPr().find(qn("a:bodyPr"))
    if body_pr is not None:
        body_pr.set("wrap", "none")
    return plot


def severity_chart(slide, data: dict, x, y, w, h):
    """Column chart of findings by severity, each bar in its status colour."""
    by_sev = data["summary"]["by_severity"]
    cats = [s for s in SEVERITY_ORDER if s in by_sev]
    cd = CategoryChartData()
    cd.categories = [c.capitalize() for c in cats]
    cd.add_series("Findings", [by_sev[c] for c in cats])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(x), Inches(y),
                                Inches(w), Inches(h), cd)
    gf.name = "chart_severity"
    plot = _quiet_chart(gf.chart, horizontal=False)
    for i, c in enumerate(cats):
        pt = plot.series[0].points[i]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = rgb(SEVERITY[c])
    return gf


def service_chart(slide, data: dict, x, y, w, h):
    """Horizontal bar chart of findings per cloud service, largest first."""
    items = sorted(data["findings_by_service"].items(), key=lambda kv: (-kv[1], kv[0]))
    cd = CategoryChartData()
    cd.categories = [k for k, _ in items]
    cd.add_series("Findings", [v for _, v in items])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(x), Inches(y),
                                Inches(w), Inches(h), cd)
    gf.name = "chart_service"
    plot = _quiet_chart(gf.chart, horizontal=True)
    fill = plot.series[0].format.fill
    fill.solid()
    fill.fore_color.rgb = rgb(COLORS["ink2"])
    return gf


def records_chart(slide, risks: list[dict], x, y, w, h):
    """Horizontal bar of records held per data store, red where the store is public."""
    rows = [r for r in risks if r["record_count"]]
    cd = CategoryChartData()
    cd.categories = [f"{r['risk_id']}  {r['asset_id']}" for r in rows]
    cd.add_series("Records", [r["record_count"] for r in rows])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(x), Inches(y),
                                Inches(w), Inches(h), cd)
    gf.name = "chart_records"
    plot = _quiet_chart(gf.chart, horizontal=True)
    plot.data_labels.number_format = "#,##0"
    # Leave room past the longest bar so its label never wraps.
    gf.chart.value_axis.maximum_scale = max(r["record_count"] for r in rows) * 1.3
    gf.chart.value_axis.minimum_scale = 0
    for i, r in enumerate(rows):
        pt = plot.series[0].points[i]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = rgb(SEVERITY["critical"] if r["exposure"] == "public"
                                            else COLORS["ink2"])
    return gf


def _zone(likelihood: int, impact: int) -> str:
    score = likelihood * impact
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


ZONE_LABELS = {
    "critical": "Act now",
    "high": "Plan this month",
    "medium": "Schedule",
    "low": "Monitor",
}


def risk_heatmap(slide, data: dict, x, y, cell=0.82, gap=0.06):
    """5 x 5 likelihood/impact grid. Each cell shows how many findings sit there,
    and the IDs of any top risks in that cell."""
    counts = {(c["likelihood"], c["impact"]): c["count"] for c in data["risk_matrix"]}
    risk_ids: dict[tuple[int, int], list[str]] = {}
    for r in data["top_risks"]:
        risk_ids.setdefault((r["likelihood"], r["impact"]), []).append(r["risk_id"])

    label_w = 0.45
    gx = x + label_w
    for row, impact in enumerate(range(5, 0, -1)):
        cy = y + row * (cell + gap)
        add_text(slide, x, cy, label_w - 0.1, cell, str(impact), size=12, color=COLORS["muted"],
                 align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE, name=f"heat_axis_i{impact}")
        for col, likelihood in enumerate(range(1, 6)):
            cx = gx + col * (cell + gap)
            zone = _zone(likelihood, impact)
            n = counts.get((likelihood, impact), 0)
            ids = risk_ids.get((likelihood, impact), [])
            fill = SEVERITY[zone] if ids else SEVERITY_SOFT[zone]
            box = add_box(slide, cx, cy, cell, cell, fill=fill, radius=0.06,
                          name=f"heat_cell_{likelihood}_{impact}")
            if n:
                on_strong = bool(ids)
                paras = [[(str(n), {"size": 18, "bold": True,
                                    "color": COLORS["white"] if on_strong else COLORS["text"]})]]
                if ids:
                    paras.append([(", ".join(ids), {"size": 10, "color": COLORS["white"]})])
                tf = box.text_frame
                tf.margin_left = tf.margin_right = Inches(0.03)
                tf.vertical_anchor = MSO_ANCHOR.MIDDLE
                tf.word_wrap = True
                for i, para in enumerate(paras):
                    p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
                    p.alignment = PP_ALIGN.CENTER
                    for t, o in para:
                        r = p.add_run()
                        r.text = t
                        r.font.size = Pt(o["size"])
                        r.font.bold = o.get("bold", False)
                        r.font.name = BODY_FONT
                        r.font.color.rgb = rgb(o["color"])

    grid_w = 5 * cell + 4 * gap
    bottom = y + 5 * (cell + gap)
    for col, likelihood in enumerate(range(1, 6)):
        add_text(slide, gx + col * (cell + gap), bottom, cell, 0.3, str(likelihood), size=12,
                 color=COLORS["muted"], align=PP_ALIGN.CENTER, name=f"heat_axis_l{likelihood}")
    add_text(slide, gx, bottom + 0.3, grid_w, 0.3, "Likelihood  →", size=12, bold=True,
             color=COLORS["text"], align=PP_ALIGN.CENTER, name="heat_axis_title_l")
    impact_lbl = add_text(slide, x - 0.85, y + 2.5 * (cell + gap) - 0.15, 1.2, 0.3, "Impact  →",
                          size=12, bold=True, color=COLORS["text"], align=PP_ALIGN.CENTER,
                          name="heat_axis_title_i")
    impact_lbl.rotation = 270
    return gx + grid_w


def heatmap_legend(slide, x, y, w):
    yy = y
    for zone in ["critical", "high", "medium", "low"]:
        add_box(slide, x, yy + 0.04, 0.28, 0.28, fill=SEVERITY[zone], radius=0.05,
                shape=MSO_SHAPE.ROUNDED_RECTANGLE, name=f"legend_{zone}")
        add_text(slide, x + 0.42, yy, w - 0.42, 0.36,
                 [[(f"{zone.capitalize()} zone", {"bold": True}), (f"  ·  {ZONE_LABELS[zone]}", {"color": COLORS["muted"]})]],
                 size=13, anchor=MSO_ANCHOR.MIDDLE)
        yy += 0.45
    return yy
