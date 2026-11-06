"""Derived figures and number checking.

Every figure in the deck is either a value from the contract JSON or one of the
derived values computed here. The tests and the narrative guard both use the
same functions, so "allowed numbers" means exactly the same thing everywhere.
"""

from __future__ import annotations

import re
from datetime import datetime

SENSITIVE_TYPES = {"PII", "financial", "health"}

# Numbers that are part of the slide design rather than the data:
# heatmap axis scale (1-5) and the 30/60/90-day roadmap windows.
STRUCTURAL_NUMBERS = {"0", "1", "2", "3", "4", "5", "30", "31", "60", "61", "90"}

# Per-risk fields written by the AI. They are shown on slides, so they are
# checked like the narrative and never count as a source of allowed numbers.
AI_TEXT_FIELDS = ("business_impact", "remediation")

_NUMBER_RE = re.compile(r"\d+(?:,\d{3})*(?:\.\d+)?")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_date(value: str) -> str:
    dt = parse_time(value)
    return f"{dt.day} {dt.strftime('%B %Y')}"


def format_datetime(value: str) -> str:
    dt = parse_time(value)
    return f"{dt.day} {dt.strftime('%b %Y, %H:%M')} UTC"


def format_int(value) -> str:
    return f"{int(value):,}"


def format_score(value: float) -> str:
    return f"{value:g}"


def lower_first(text: str) -> str:
    """Lower-case the first letter for use mid-sentence, unless the first word
    is an acronym or name such as 'RDS', 'S3' or 'IAM'."""
    first = text.split(" ", 1)[0]
    if len(first) > 1 and not first[1:].islower():
        return text
    return text[:1].lower() + text[1:]


def window_label(window: str) -> str:
    start, end = window.split("-")
    return f"{start}–{end} days"


def derive(data: dict) -> dict:
    """Figures computed from the contract and shown on slides."""
    s = data["summary"]
    sev = s["by_severity"]
    total = s["total_findings"]
    crit_high = sev.get("critical", 0) + sev.get("high", 0)
    risks = data["top_risks"]
    windows = {}
    for r in risks:
        windows[r["remediation_window"]] = windows.get(r["remediation_window"], 0) + 1
    return {
        "critical_high": crit_high,
        "pct_critical_high": round(100 * crit_high / total) if total else 0,
        "detail_risks": min(3, len(risks)),
        "top_risk_count": len(risks),
        "report_date": format_date(data["generated_at"]),
        "anomaly_times": [format_datetime(a["timestamp"]) for a in data["anomalies"]],
        "window_counts": windows,
        "critical_zone_findings": sum(
            c["count"] for c in data["risk_matrix"] if c["likelihood"] * c["impact"] >= 20),
        "exposed_records": sum(
            r["record_count"] or 0 for r in risks
            if r["exposure"] == "public" and r["data_sensitivity"] in SENSITIVE_TYPES),
    }


def normalise(token: str) -> str:
    """'48,200' -> '48200', '60.0' -> '60', '02' -> '2', '1.50' -> '1.5'."""
    token = token.replace(",", "")
    if "." in token:
        token = token.rstrip("0").rstrip(".")
    return str(int(token)) if token.isdigit() else token


def number_tokens(text: str) -> set[str]:
    return {normalise(m) for m in _NUMBER_RE.findall(text)}


def _walk(value, out: set[str]) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float)):
        out.add(normalise(repr(float(value)) if isinstance(value, float) else str(value)))
    elif isinstance(value, str):
        out |= number_tokens(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if k in AI_TEXT_FIELDS:
                continue
            _walk(k, out)
            _walk(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _walk(v, out)


def allowed_numbers(data: dict) -> set[str]:
    """Every number that may legitimately appear in the deck. AI-written fields
    (narrative and per-risk text) are excluded: they are checked, not trusted."""
    out: set[str] = set(STRUCTURAL_NUMBERS)
    _walk(data, out)
    _walk(derive(data), out)
    return out


def unknown_numbers(text: str, allowed: set[str]) -> set[str]:
    return number_tokens(text) - allowed
