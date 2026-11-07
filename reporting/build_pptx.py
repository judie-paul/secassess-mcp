"""Build the security assessment deck from the contract JSON.

    build_report(data, narrative, out_dir, fmt="pptx") -> path

`data` (from the backend) supplies every number and chart.
`narrative` (written by the AI) supplies only prose: executive_summary,
key_messages and correlated_story. Any number in the narrative that does not
exist in the data is rejected, so the AI cannot put an invented figure in the deck.

Command line:
    python -m reporting.build_pptx contracts/report_data.example.json \
        --narrative contracts/narrative.example.json --out examples --fmt pdf
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches

from . import charts
from .contract import validate_contract
from .export_pdf import export_pdf
from .metrics import (
    AI_TEXT_FIELDS, SENSITIVE_TYPES, allowed_numbers, derive, format_date, format_datetime,
    format_int, format_score, lower_first, parse_time, unknown_numbers, window_label,
)
from .template.theme import (
    COLORS, CONTENT_W, HEAD_FONT, MARGIN, SEVERITY, SEVERITY_SOFT, SLIDE_H, SLIDE_W,
    SOURCE_LABELS, add_box, add_footer, add_number_badge, add_pill, add_text, add_title,
    set_background, style_table,
)

NARRATIVE_LIMITS = {"executive_summary": 480, "key_messages": 90, "correlated_story": 330}


class NarrativeError(ValueError):
    pass


# --------------------------------------------------------------------------- narrative

def default_narrative(data: dict, m: dict) -> dict:
    """Plain, data-only wording used when no AI narrative is supplied."""
    s = data["summary"]
    top = data["top_risks"][0]
    summary = (
        f"This assessment covers {s['total_findings']} findings across {s['total_assets']} assets. "
        f"{m['critical_high']} are critical or high severity, {s['sensitive_assets_exposed']} of "
        f"{s['sensitive_assets']} sensitive data stores are exposed, and {s['anomalies_detected']} "
        f"suspicious access events were detected. The highest risk is: {lower_first(top['title'])}."
    )
    keys = [_fit(f"Resolve {r['risk_id']}: {lower_first(r['title'])}", NARRATIVE_LIMITS["key_messages"])
            for r in data["top_risks"][:3]]
    story_risk = _story_risk(data)
    # One signal per source, in the order the correlation slide shows them.
    story = ""
    for source in ("findings", "data_inventory", "auth_logs"):
        ev = next((e for e in story_risk["evidence"] if e["source"] == source), None)
        if ev:
            sentence = ev["detail"].rstrip(".") + "."
            if len(story) + len(sentence) + 1 > NARRATIVE_LIMITS["correlated_story"]:
                break
            story = f"{story} {sentence}".strip()
    return {"executive_summary": summary, "key_messages": keys, "correlated_story": story}


def _fit(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def check_risk_text(data: dict, strict_numbers: bool = True) -> None:
    """AI-written business_impact / remediation must not contain invented numbers."""
    if not strict_numbers:
        return
    allowed = allowed_numbers(data)
    problems = []
    for r in data["top_risks"]:
        for field in AI_TEXT_FIELDS:
            bad = unknown_numbers(r.get(field) or "", allowed)
            if bad:
                problems.append(f"{r['risk_id']} {field} contains numbers not found in the data: {sorted(bad)}")
    if problems:
        raise NarrativeError("Risk text rejected:\n- " + "\n- ".join(problems))


def check_narrative(narrative: dict, data: dict, strict_numbers: bool = True) -> None:
    problems = []
    allowed = allowed_numbers(data)
    for key, limit in NARRATIVE_LIMITS.items():
        value = narrative.get(key)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        if key == "key_messages" and not (1 <= len(items) <= 3):
            problems.append("key_messages must have 1 to 3 items")
        for item in items:
            if not isinstance(item, str):
                problems.append(f"{key} must be text")
                continue
            if len(item) > limit:
                problems.append(f"{key} is {len(item)} characters; keep it under {limit}")
            if strict_numbers:
                bad = unknown_numbers(item, allowed)
                if bad:
                    problems.append(f"{key} contains numbers not found in the data: {sorted(bad)}")
    if problems:
        raise NarrativeError("Narrative rejected:\n- " + "\n- ".join(problems))


def _story_risk(data: dict) -> dict:
    """The risk that best shows correlation: a top risk with signals from all
    three sources, falling back to the highest-ranked risk."""
    for r in data["top_risks"]:
        if {e["source"] for e in r["evidence"]} >= {"findings", "data_inventory", "auth_logs"}:
            return r
    return data["top_risks"][0]


# --------------------------------------------------------------------------- slides

def _new_slide(prs, dark=False):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_background(slide, COLORS["ink"] if dark else COLORS["bg"])
    return slide


def _finish(slide, data, page, notes=None):
    add_footer(slide, f"{data['organisation']}  ·  Cloud security assessment", page)
    if notes:
        slide.notes_slide.notes_text_frame.text = notes


def slide_title(prs, data, m):
    s = _new_slide(prs, dark=True)
    # motif: a small likelihood/impact grid echoing the heatmap slide
    for row in range(5):
        for col in range(5):
            zone = charts._zone(col + 1, 5 - row)
            solid = (col + 1) * (5 - row) >= 16
            add_box(s, 9.15 + col * 0.66, 1.65 + row * 0.66, 0.56, 0.56,
                    fill=SEVERITY[zone] if solid else COLORS["ink2"], radius=0.06,
                    name=f"motif_{row}_{col}")
    add_text(s, MARGIN, 2.0, 8.0, 0.35, "CLOUD SECURITY ASSESSMENT", size=13, bold=True,
             color=COLORS["on_dark_muted"])
    add_text(s, MARGIN, 2.4, 8.0, 1.3, data["organisation"], size=44, bold=True,
             font=HEAD_FONT, color=COLORS["white"], anchor=MSO_ANCHOR.TOP)
    add_text(s, MARGIN, 3.85, 8.0, 0.8,
             "Configuration risks, sensitive data exposure and suspicious activity",
             size=20, color=COLORS["on_dark_muted"])
    add_text(s, MARGIN, 4.9, 8.0, 0.4, m["report_date"], size=16, bold=True, color=COLORS["white"])
    add_text(s, MARGIN, 6.6, 12.0, 0.35,
             "Based on configuration findings, data inventory and authentication logs",
             size=12, color=COLORS["on_dark_muted"], name="chrome_footer")


def slide_exec_summary(prs, data, m, narrative):
    s = _new_slide(prs)
    add_title(s, "Executive summary", kicker="Overview")
    add_text(s, MARGIN, 1.75, 6.9, 2.3, narrative["executive_summary"], size=16,
             line_spacing=1.1, shrink=True, name="narrative_summary")
    add_text(s, MARGIN, 4.2, 6.9, 0.35, "What to do first", size=15, bold=True,
             color=COLORS["ink"])
    for i, msg in enumerate(narrative["key_messages"][:3]):
        y = 4.7 + i * 0.68
        add_number_badge(s, MARGIN, y, i + 1, d=0.42, size=14)
        add_text(s, MARGIN + 0.62, y - 0.04, 6.25, 0.6, msg, size=15, anchor=MSO_ANCHOR.MIDDLE,
                 shrink=True, name=f"narrative_key_{i + 1}")

    sm = data["summary"]
    tiles = [
        (format_int(sm["total_findings"]), "findings across " + format_int(sm["total_assets"]) + " assets", COLORS["ink"]),
        (format_int(m["critical_high"]), "critical or high severity", SEVERITY["critical"]),
        (f"{sm['sensitive_assets_exposed']} of {sm['sensitive_assets']}", "sensitive data stores exposed", COLORS["ink"]),
        (format_int(sm["anomalies_detected"]), "suspicious access events", COLORS["ink"]),
    ]
    for i, (value, label, color) in enumerate(tiles):
        x = 8.0 + (i % 2) * 2.48
        y = 1.75 + (i // 2) * 2.5
        add_box(s, x, y, 2.25, 2.3, fill=COLORS["tint"], radius=0.12, name=f"tile_bg_{i}")
        add_text(s, x + 0.25, y + 0.35, 1.85, 0.9, value, size=40, bold=True, color=color,
                 font=HEAD_FONT, name=f"tile_value_{i}")
        add_text(s, x + 0.25, y + 1.3, 1.85, 0.8, label, size=13, color=COLORS["muted"],
                 name=f"tile_label_{i}")
    _finish(s, data, 2)


def slide_posture(prs, data, m):
    s = _new_slide(prs)
    total = data["summary"]["total_findings"]
    add_title(s, f"{m['critical_high']} of {total} findings are critical or high severity",
              kicker="Security posture")
    add_text(s, MARGIN, 1.75, 5.6, 0.35, "Findings by severity", size=15, bold=True, color=COLORS["ink"])
    add_text(s, MARGIN, 2.1, 5.6, 0.3, f"{m['pct_critical_high']}% need action within 60 days",
             size=13, color=COLORS["muted"])
    charts.severity_chart(s, data, MARGIN, 2.5, 5.6, 4.25)
    add_text(s, 7.0, 1.75, 5.73, 0.35, "Findings by cloud service", size=15, bold=True, color=COLORS["ink"])
    add_text(s, 7.0, 2.1, 5.73, 0.3, "Where the configuration problems are concentrated",
             size=13, color=COLORS["muted"])
    charts.service_chart(s, data, 7.0, 2.5, 5.73, 4.25)
    _finish(s, data, 3, "Source: summary.by_severity and findings_by_service from the backend.")


def slide_heatmap(prs, data, m):
    s = _new_slide(prs)
    n = m["critical_zone_findings"]
    add_title(s, f"{n} finding{'s' if n != 1 else ''} sit{'' if n != 1 else 's'} in the critical zone",
              kicker="Risk heatmap")
    charts.risk_heatmap(s, data, 1.45, 1.7)
    x = 7.3
    w = 13.333 - MARGIN - x
    yy = charts.heatmap_legend(s, x, 1.75, w)
    add_text(s, x, yy + 0.1, w, 0.65,
             "Numbers show how many findings sit in each cell. Solid cells contain a top risk.",
             size=13, color=COLORS["muted"])
    add_text(s, x, yy + 0.9, w, 0.35, "Top risks on the map", size=15, bold=True, color=COLORS["ink"])
    for i, r in enumerate(data["top_risks"][:5]):
        y = yy + 1.35 + i * 0.42
        add_pill(s, x, y + 0.04, r["risk_id"], SEVERITY[r["severity"]], size=10, w=0.75)
        add_text(s, x + 0.9, y, w - 0.9, 0.38, r["title"], size=13, anchor=MSO_ANCHOR.MIDDLE)
    _finish(s, data, 4, "Likelihood and impact are 1-5 scores from the backend (see methodology).")


def slide_sensitive(prs, data, m):
    s = _new_slide(prs)
    sm = data["summary"]
    add_title(s, f"{sm['sensitive_assets_exposed']} of {sm['sensitive_assets']} sensitive data stores are exposed",
              kicker="Sensitive data exposure")
    add_box(s, MARGIN, 1.75, 3.5, 4.95, fill=COLORS["tint"], radius=0.12)
    add_text(s, MARGIN + 0.3, 2.05, 2.9, 0.4, "Records at risk", size=14, bold=True, color=COLORS["muted"])
    add_text(s, MARGIN + 0.3, 2.45, 2.9, 0.9, format_int(m["exposed_records"]), size=40, bold=True,
             font=HEAD_FONT, color=SEVERITY["critical"], name="stat_exposed_records")
    add_text(s, MARGIN + 0.3, 3.4, 2.9, 1.2,
             "personal or financial records held in publicly exposed stores among the top risks",
             size=13, color=COLORS["muted"])
    add_text(s, MARGIN + 0.3, 4.75, 2.9, 1.7,
             "Exposure combined with sensitive data doubles a risk's score; suspicious access raises it further.",
             size=13, color=COLORS["text"])

    rows = [r for r in data["top_risks"] if r["data_sensitivity"] in SENSITIVE_TYPES][:6]
    headers = ["Risk", "Asset", "Data", "Records", "Exposure", "Suspicious access"]
    widths = [0.85, 2.35, 1.05, 1.2, 1.15, 1.63]
    x0 = 4.5
    shape = s.shapes.add_table(len(rows) + 1, len(headers), Inches(x0), Inches(1.75),
                               Inches(sum(widths)), Inches(0.5 * (len(rows) + 1)))
    shape.name = "table_sensitive"
    tbl = shape.table
    for i, wd in enumerate(widths):
        tbl.columns[i].width = Inches(wd)
    for c, h in enumerate(headers):
        tbl.cell(0, c).text = h
    for r_i, r in enumerate(rows, start=1):
        vals = [r["risk_id"], r["asset_id"], r["data_sensitivity"],
                format_int(r["record_count"]) if r["record_count"] is not None else "n/a",
                r["exposure"].capitalize(), "Yes" if r["anomalous_access"] else "No"]
        for c, v in enumerate(vals):
            tbl.cell(r_i, c).text = v
    for row in tbl.rows:
        row.height = Inches(0.5)
    style_table(tbl, size=12, col_align={3: PP_ALIGN.RIGHT})
    for r_i, r in enumerate(rows, start=1):
        if r["exposure"] == "public":
            for run in tbl.cell(r_i, 4).text_frame.paragraphs[0].runs:
                run.font.bold = True
                run.font.color.rgb = charts.rgb(SEVERITY["critical"])
    chart_y = 1.75 + 0.5 * (len(rows) + 1) + 0.35
    if chart_y < 5.2 and any(r["record_count"] for r in rows):
        add_text(s, x0, chart_y, sum(widths), 0.35,
                 [[("Records held per data store", {"bold": True, "color": COLORS["ink"]}),
                   ("   red = publicly exposed", {"color": COLORS["muted"], "size": 12})]], size=15)
        charts.records_chart(s, rows, x0, chart_y + 0.4, sum(widths), 6.75 - chart_y - 0.4)
    _finish(s, data, 5, "Source: data inventory joined to configuration findings by asset_id.")


def slide_anomalies(prs, data, m):
    s = _new_slide(prs)
    n = data["summary"]["anomalies_detected"]
    add_title(s, f"{n} suspicious access events were detected", kicker="Suspicious activity")
    risk_by_asset = {r["asset_id"]: r["risk_id"] for r in data["top_risks"]}
    rank_by_asset = {r["asset_id"]: r["rank"] for r in data["top_risks"]}
    # Events linked to the highest-ranked risks first, then the most recent.
    ordered = sorted(data["anomalies"], key=lambda a: parse_time(a["timestamp"]), reverse=True)
    ordered.sort(key=lambda a: rank_by_asset.get(a["asset_id"], 99))
    shown = ordered[:3]
    gap = 0.3
    w = (CONTENT_W - gap * 2) / 3
    for i, a in enumerate(shown):
        x = MARGIN + i * (w + gap)
        y = 1.75
        add_box(s, x, y, w, 4.95, fill=COLORS["tint"], radius=0.12)
        t = data["anomaly_types"][a["type"]]
        add_text(s, x + 0.3, y + 0.3, w - 0.6, 0.45, t["label"], size=19, bold=True,
                 font=HEAD_FONT, color=COLORS["ink"])
        rows = [("User", a["user"]), ("Asset", a["asset_id"]), ("Country", a["country"]),
                ("When", format_datetime(a["timestamp"]))]
        for j, (k, v) in enumerate(rows):
            yy = y + 0.95 + j * 0.42
            add_text(s, x + 0.3, yy, 0.95, 0.35, k, size=13, color=COLORS["muted"])
            add_text(s, x + 1.25, yy, w - 1.55, 0.35, v, size=13, bold=True)
        add_text(s, x + 0.3, y + 2.75, w - 0.6, 0.85, a["detail"], size=14)
        add_text(s, x + 0.3, y + 3.6, w - 0.6, 0.8, "Rule: " + t["description"], size=12,
                 italic=True, color=COLORS["muted"])
        if a["asset_id"] in risk_by_asset:
            add_pill(s, x + 0.3, y + 4.45, f"Linked to {risk_by_asset[a['asset_id']]}",
                     COLORS["accent"], size=11)
    if len(data["anomalies"]) > 3:
        add_text(s, MARGIN, 6.72, 10, 0.25,
                 f"Showing 3 of {len(data['anomalies'])} events: those linked to the highest-ranked risks first",
                 size=11, color=COLORS["muted"])
    _finish(s, data, 6, "Source: authentication logs, anomaly rules defined in the backend config.")


def slide_top_risk(prs, data, m, r, page):
    s = _new_slide(prs)
    sev = r["severity"]
    add_title(s, r["title"], kicker=f"Top risk {r['rank']} of {m['top_risk_count']}  ·  {r['service']}")

    # left: score card
    add_box(s, MARGIN, 1.75, 3.7, 4.95, fill=SEVERITY_SOFT[sev], radius=0.12)
    add_pill(s, MARGIN + 0.3, 2.05, sev.upper(), SEVERITY[sev], size=11)
    add_text(s, MARGIN + 0.3, 2.5, 3.1, 0.3, "Risk score", size=13, color=COLORS["muted"])
    add_text(s, MARGIN + 0.3, 2.78, 3.1, 0.9, format_score(r["score"]), size=48, bold=True,
             font=HEAD_FONT, color=SEVERITY[sev], name="score_value")
    b = r["score_breakdown"]
    factors = [
        ("Severity", sev, b["severity"], ""),
        ("Exposure", r["exposure"], b["exposure"], "× "),
        ("Data", r["data_sensitivity"], b["data_sensitivity"], "× "),
        ("Activity", "suspicious" if r["anomalous_access"] else "normal", b["activity"], "× "),
    ]
    for j, (name, val, num, op) in enumerate(factors):
        yy = 3.85 + j * 0.42
        add_text(s, MARGIN + 0.3, yy, 2.3, 0.35,
                 [[(name + "  ", {"color": COLORS["muted"]}), (val, {"bold": True})]], size=13)
        add_text(s, MARGIN + 2.5, yy, 0.9, 0.35, op + format_score(num), size=13, bold=True,
                 align=PP_ALIGN.RIGHT)
    add_box(s, MARGIN + 0.3, 5.58, 3.1, 0.02, fill=COLORS["faint"], shape=MSO_SHAPE.RECTANGLE)
    add_text(s, MARGIN + 0.3, 5.68, 2.3, 0.35, "Score", size=13, bold=True)
    add_text(s, MARGIN + 2.5, 5.68, 0.9, 0.35, "= " + format_score(r["score"]), size=13, bold=True,
             align=PP_ALIGN.RIGHT)
    add_text(s, MARGIN + 0.3, 6.15, 3.1, 0.35, "Asset: " + r["asset_id"], size=12, color=COLORS["muted"])

    # middle: evidence
    x = 4.65
    w = 4.3
    add_text(s, x, 1.75, w, 0.35, "Evidence", size=15, bold=True, color=COLORS["ink"])
    for j, ev in enumerate(r["evidence"][:4]):
        yy = 2.25 + j * 1.1
        add_text(s, x, yy, w, 0.3,
                 [[(SOURCE_LABELS[ev["source"]].upper(), {"bold": True, "color": COLORS["accent"]}),
                   ("   " + ev["ref"], {"color": COLORS["muted"]})]], size=11)
        add_text(s, x, yy + 0.3, w, 0.7, ev["detail"], size=14, shrink=True)

    # right: impact and fix
    x = 9.25
    w = 13.333 - MARGIN - x
    add_box(s, x, 1.75, w, 2.35, fill=COLORS["tint"], radius=0.12)
    add_text(s, x + 0.25, 1.95, w - 0.5, 0.35, "Business impact", size=15, bold=True, color=COLORS["ink"])
    add_text(s, x + 0.25, 2.35, w - 0.5, 1.6, r["business_impact"] or "Not yet described.", size=14,
             shrink=True, color=None if r["business_impact"] else COLORS["muted"])
    add_box(s, x, 4.3, w, 2.4, fill=COLORS["accent_soft"], radius=0.12)
    add_text(s, x + 0.25, 4.5, w - 0.5, 0.35, "Recommended fix", size=15, bold=True, color=COLORS["ink"])
    add_text(s, x + 0.25, 4.9, w - 0.5, 1.25, r["remediation"] or "Not yet described.", size=14,
             shrink=True, color=None if r["remediation"] else COLORS["muted"])
    add_text(s, x + 0.25, 6.2, w - 0.5, 0.35, "Complete within " + window_label(r["remediation_window"]),
             size=13, bold=True, color=COLORS["accent"])
    refs = ", ".join(f"{e['source']}:{e['ref']}" for e in r["evidence"])
    _finish(s, data, page, f"Evidence references: {refs}")


def slide_correlation(prs, data, m, narrative):
    s = _new_slide(prs)
    r = _story_risk(data)
    add_title(s, "Three signals, one asset: why " + r["risk_id"] + " ranks first"
              if r["rank"] == 1 else "How signals combine for " + r["risk_id"],
              kicker="Correlated risk")
    steps = [("Misconfiguration", "findings"), ("Sensitive data", "data_inventory"),
             ("Suspicious access", "auth_logs")]
    by_source = {}
    for ev in r["evidence"]:
        by_source.setdefault(ev["source"], ev)
    card_w, gap, y, h = 2.72, 0.42, 1.8, 3.05
    for i, (heading, src) in enumerate(steps):
        x = MARGIN + i * (card_w + gap)
        ev = by_source.get(src)
        add_box(s, x, y, card_w, h, fill=COLORS["tint"], radius=0.12)
        add_number_badge(s, x + 0.25, y + 0.25, i + 1, d=0.42, size=14)
        add_text(s, x + 0.25, y + 0.85, card_w - 0.5, 0.4, heading, size=17, bold=True,
                 font=HEAD_FONT, color=COLORS["ink"])
        add_text(s, x + 0.25, y + 1.27, card_w - 0.5, 0.3,
                 [[(SOURCE_LABELS[src].upper(), {"bold": True}),
                   (("  " + ev["ref"]) if ev else "", {"color": COLORS["muted"]})]],
                 size=10, color=COLORS["accent"])
        add_text(s, x + 0.25, y + 1.65, card_w - 0.5, 1.25,
                 ev["detail"] if ev else "No signal from this source", size=14,
                 color=COLORS["text"] if ev else COLORS["muted"], shrink=True)
        arrow_x = x + card_w + 0.08
        add_box(s, arrow_x, y + h / 2 - 0.13, gap - 0.16, 0.26, fill=COLORS["faint"],
                shape=MSO_SHAPE.RIGHT_ARROW, name=f"arrow_{i}")
    x = MARGIN + 3 * (card_w + gap)
    rw = 13.333 - MARGIN - x
    add_box(s, x, y, rw, h, fill=SEVERITY[r["severity"]], radius=0.12)
    add_text(s, x + 0.25, y + 0.3, rw - 0.5, 0.35, "Combined risk score", size=14, bold=True,
             color=COLORS["white"])
    add_text(s, x + 0.25, y + 0.75, rw - 0.5, 1.0, format_score(r["score"]), size=54, bold=True,
             font=HEAD_FONT, color=COLORS["white"])
    add_text(s, x + 0.25, y + 1.95, rw - 0.5, 0.9,
             [f"Rank {r['rank']} of {m['top_risk_count']} top risks", r["asset_id"]],
             size=13, color=COLORS["white"])
    add_box(s, MARGIN, 5.15, CONTENT_W, 1.55, fill=COLORS["accent_soft"], radius=0.12)
    add_text(s, MARGIN + 0.3, 5.3, CONTENT_W - 0.6, 1.25, narrative["correlated_story"], size=16,
             anchor=MSO_ANCHOR.MIDDLE, shrink=True, name="narrative_story")
    _finish(s, data, 10, "Signals are joined on asset_id across findings, data inventory and authentication logs.")


def slide_roadmap(prs, data, m):
    s = _new_slide(prs)
    add_title(s, "Remediation roadmap", kicker="Next 90 days")
    lanes = [("0-30", "Immediate"), ("31-60", "Next"), ("61-90", "Planned")]
    lane_h, gap, y0 = 1.58, 0.12, 1.7
    label_w = 2.0
    for i, (window, label) in enumerate(lanes):
        y = y0 + i * (lane_h + gap)
        add_box(s, MARGIN, y, label_w, lane_h, fill=COLORS["ink"] if i == 0 else COLORS["ink2"], radius=0.12)
        add_text(s, MARGIN + 0.25, y + 0.35, label_w - 0.4, 0.45, window_label(window), size=19,
                 bold=True, font=HEAD_FONT, color=COLORS["white"])
        add_text(s, MARGIN + 0.25, y + 0.85, label_w - 0.4, 0.35, label, size=13,
                 color=COLORS["on_dark_muted"])
        risks = [r for r in data["top_risks"] if r["remediation_window"] == window]
        area_x = MARGIN + label_w + 0.2
        area_w = 13.333 - MARGIN - area_x
        if not risks:
            add_box(s, area_x, y, area_w, lane_h, fill=COLORS["tint"], radius=0.12)
            add_text(s, area_x + 0.3, y, area_w - 0.6, lane_h, "No top risks fall in this window",
                     size=13, color=COLORS["muted"], anchor=MSO_ANCHOR.MIDDLE)
            continue
        shown = risks[:3] if len(risks) <= 3 else risks[:2]
        slots = 3
        cw = (area_w - (slots - 1) * 0.2) / slots
        for j, r in enumerate(shown):
            cx = area_x + j * (cw + 0.2)
            add_box(s, cx, y, cw, lane_h, fill=SEVERITY_SOFT[r["severity"]], radius=0.12)
            add_pill(s, cx + 0.2, y + 0.15, f"{r['risk_id']}  ·  {r['severity'].upper()}",
                     SEVERITY[r["severity"]], size=10)
            add_text(s, cx + 0.2, y + 0.5, cw - 0.4, 0.45, r["title"], size=13, bold=True,
                     shrink=True)
            add_text(s, cx + 0.2, y + 0.95, cw - 0.4, 0.58, r["remediation"] or "Not yet described.",
                     size=11, color=COLORS["muted"], shrink=True)
        if len(risks) > 3:
            cx = area_x + 2 * (cw + 0.2)
            add_box(s, cx, y, cw, lane_h, fill=COLORS["tint"], radius=0.12)
            add_text(s, cx + 0.2, y, cw - 0.4, lane_h, f"+{len(risks) - 2} more in this window",
                     size=14, bold=True, color=COLORS["muted"], anchor=MSO_ANCHOR.MIDDLE)
    _finish(s, data, 11, "Windows come from scoring_model.remediation_windows (by severity).")


def slide_methodology(prs, data, m):
    s = _new_slide(prs)
    model = data["scoring_model"]
    add_title(s, "How this assessment was produced", kicker="Methodology")
    add_text(s, MARGIN, 1.75, 6.0, 0.35, "Risk scoring", size=15, bold=True, color=COLORS["ink"])
    add_box(s, MARGIN, 2.2, 6.0, 0.6, fill=COLORS["accent_soft"], radius=0.1)
    add_text(s, MARGIN + 0.25, 2.2, 5.5, 0.6, "Risk = severity × exposure × data sensitivity × activity",
             size=14, bold=True, color=COLORS["ink"], anchor=MSO_ANCHOR.MIDDLE)
    names = {"severity": "Severity", "exposure": "Exposure", "data_sensitivity": "Data sensitivity",
             "activity": "Activity"}
    rows = [(names.get(k, k), "   ".join(f"{lbl} {format_score(v)}" for lbl, v in vals.items()))
            for k, vals in model["factors"].items()]
    shape = s.shapes.add_table(len(rows) + 1, 2, Inches(MARGIN), Inches(3.0), Inches(6.0),
                               Inches(0.45 * (len(rows) + 1)))
    shape.name = "table_factors"
    tbl = shape.table
    tbl.columns[0].width = Inches(1.7)
    tbl.columns[1].width = Inches(4.3)
    tbl.cell(0, 0).text, tbl.cell(0, 1).text = "Factor", "Values"
    for i, (a, b) in enumerate(rows, start=1):
        tbl.cell(i, 0).text, tbl.cell(i, 1).text = a, b
    for row in tbl.rows:
        row.height = Inches(0.45)
    style_table(tbl, size=12)
    add_text(s, MARGIN, 5.4, 6.0, 0.45, "Likelihood: " + model.get("likelihood_rule", ""), size=12,
             color=COLORS["muted"])
    add_text(s, MARGIN, 5.85, 6.0, 0.45,
             "Sources: configuration findings · data inventory · authentication logs", size=12,
             color=COLORS["muted"])
    add_text(s, MARGIN, 6.3, 6.0, 0.4,
             f"Scoring model version {model['version']}  ·  data generated {format_date(data['generated_at'])}",
             size=12, color=COLORS["muted"])

    x, w = 7.1, 13.333 - MARGIN - 7.1
    add_text(s, x, 1.75, w, 0.35, "Anomaly rules", size=15, bold=True, color=COLORS["ink"])
    types = list(data["anomaly_types"].values())
    shown = types[:6]
    row_h = min(0.8, 4.6 / max(1, len(shown)))
    for i, t in enumerate(shown):
        y = 2.2 + i * row_h
        add_text(s, x, y, w, row_h - 0.05, [[(t["label"], {"bold": True})],
                                            [(t["description"], {"color": COLORS["muted"], "size": 12})]],
                 size=13, shrink=True)
    if len(types) > len(shown):
        add_text(s, x, 6.5, w, 0.3, f"+{len(types) - len(shown)} more rules in the backend config",
                 size=11, color=COLORS["muted"])
    _finish(s, data, 12)


# --------------------------------------------------------------------------- entry point

def build_report(data: dict, narrative: dict | None = None, out_dir: str | Path = "output",
                 fmt: str = "pptx", filename: str = "security_assessment",
                 strict_numbers: bool = True) -> str:
    """Build the deck. Returns the path of the .pptx (or .pdf when fmt="pdf")."""
    if fmt not in ("pptx", "pdf"):
        raise ValueError("fmt must be 'pptx' or 'pdf'")
    validate_contract(data)
    check_risk_text(data, strict_numbers)
    m = derive(data)
    merged = default_narrative(data, m)
    if narrative:
        check_narrative(narrative, data, strict_numbers)
        merged.update({k: v for k, v in narrative.items() if k in NARRATIVE_LIMITS and v})

    prs = Presentation()
    prs.slide_width, prs.slide_height = SLIDE_W, SLIDE_H
    when = parse_time(data["generated_at"]).replace(tzinfo=None)
    cp = prs.core_properties
    cp.title = f"{data['organisation']} – Cloud security assessment"
    cp.author = "secassess-mcp"
    cp.created = cp.modified = when
    cp.revision = 1

    slide_title(prs, data, m)
    slide_exec_summary(prs, data, m, merged)
    slide_posture(prs, data, m)
    slide_heatmap(prs, data, m)
    slide_sensitive(prs, data, m)
    slide_anomalies(prs, data, m)
    for i, r in enumerate(data["top_risks"][:3]):
        slide_top_risk(prs, data, m, r, page=7 + i)
    slide_correlation(prs, data, m, merged)
    slide_roadmap(prs, data, m)
    slide_methodology(prs, data, m)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pptx_path = out_dir / f"{filename}.pptx"
    prs.save(pptx_path)
    if fmt == "pdf":
        return export_pdf(pptx_path, out_dir)
    return str(pptx_path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the security assessment deck.")
    ap.add_argument("data", help="contract JSON from the backend")
    ap.add_argument("--narrative", help="narrative JSON written by the AI")
    ap.add_argument("--out", default="output")
    ap.add_argument("--fmt", choices=["pptx", "pdf"], default="pptx")
    ap.add_argument("--name", default="security_assessment")
    args = ap.parse_args(argv)
    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    narrative = json.loads(Path(args.narrative).read_text(encoding="utf-8")) if args.narrative else None
    print(build_report(data, narrative, args.out, args.fmt, args.name))


if __name__ == "__main__":
    main()
