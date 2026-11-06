"""Load and check the contract JSON that the backend hands to the report builder.

The checks are about internal consistency, not style: totals must add up,
every score must equal the product of its factors, and every factor must match
the scoring model the backend says it used. If any of these fail, the deck
would show numbers that contradict each other, so we refuse to build it.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

REQUIRED_KEYS = [
    "schema_version", "generated_at", "organisation", "scoring_model",
    "anomaly_types", "summary", "findings_by_service", "risk_matrix",
    "top_risks", "anomalies",
]

RISK_KEYS = [
    "rank", "risk_id", "asset_id", "service", "title", "severity", "exposure",
    "data_sensitivity", "record_count", "anomalous_access", "score",
    "score_breakdown", "likelihood", "impact", "evidence", "business_impact",
    "remediation", "remediation_window",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
EVIDENCE_SOURCES = {"findings", "data_inventory", "auth_logs"}


class ContractError(ValueError):
    """Raised when the contract JSON is missing data or contradicts itself."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("Contract check failed:\n- " + "\n- ".join(problems))


def load_contract(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate_contract(data: dict, raise_on_error: bool = True) -> list[str]:
    """Return a list of problems (empty if the data is consistent)."""
    problems: list[str] = []

    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        problems.append(f"missing top-level keys: {missing}")
        if raise_on_error:
            raise ContractError(problems)
        return problems

    summary = data["summary"]
    total = summary.get("total_findings")
    by_sev = summary.get("by_severity", {})

    if sum(by_sev.values()) != total:
        problems.append(f"summary.by_severity adds up to {sum(by_sev.values())}, not total_findings {total}")
    if sum(data["findings_by_service"].values()) != total:
        problems.append(f"findings_by_service adds up to {sum(data['findings_by_service'].values())}, not {total}")
    matrix_total = sum(c["count"] for c in data["risk_matrix"])
    if matrix_total != total:
        problems.append(f"risk_matrix counts add up to {matrix_total}, not {total}")
    for cell in data["risk_matrix"]:
        if not (1 <= cell["likelihood"] <= 5 and 1 <= cell["impact"] <= 5):
            problems.append(f"risk_matrix cell out of range: {cell}")
    if summary.get("anomalies_detected") != len(data["anomalies"]):
        problems.append(f"summary.anomalies_detected is {summary.get('anomalies_detected')} but {len(data['anomalies'])} anomalies listed")
    if summary.get("sensitive_assets_exposed", 0) > summary.get("sensitive_assets", 0):
        problems.append("sensitive_assets_exposed is larger than sensitive_assets")

    model = data["scoring_model"]
    factors = model.get("factors", {})
    windows = model.get("remediation_windows", {})
    anomaly_ids = {a["anomaly_id"] for a in data["anomalies"]}

    for a in data["anomalies"]:
        if a.get("type") not in data["anomaly_types"]:
            problems.append(f"anomaly {a.get('anomaly_id')} has unknown type {a.get('type')!r}")

    risks = data["top_risks"]
    if not risks:
        problems.append("top_risks is empty")
    for i, r in enumerate(risks):
        rid = r.get("risk_id", f"top_risks[{i}]")
        missing_r = [k for k in RISK_KEYS if k not in r]
        if missing_r:
            problems.append(f"{rid}: missing fields {missing_r}")
            continue
        if r["rank"] != i + 1:
            problems.append(f"{rid}: rank is {r['rank']} but it is item {i + 1} in the list")
        if i and r["score"] > risks[i - 1]["score"]:
            problems.append(f"{rid}: list is not sorted by score (highest first)")
        if r["severity"] not in SEVERITY_ORDER:
            problems.append(f"{rid}: unknown severity {r['severity']!r}")

        b = r["score_breakdown"]
        product = b["severity"] * b["exposure"] * b["data_sensitivity"] * b["activity"]
        if not math.isclose(product, r["score"], abs_tol=0.01):
            problems.append(f"{rid}: score {r['score']} does not equal its breakdown product {round(product, 2)}")

        expected = {
            "severity": factors.get("severity", {}).get(r["severity"]),
            "exposure": factors.get("exposure", {}).get(r["exposure"]),
            "data_sensitivity": factors.get("data_sensitivity", {}).get(r["data_sensitivity"]),
            "activity": factors.get("activity", {}).get("anomalous" if r["anomalous_access"] else "normal"),
        }
        for name, want in expected.items():
            if want is None:
                problems.append(f"{rid}: scoring_model has no {name} factor for this risk")
            elif not math.isclose(b[name], want):
                problems.append(f"{rid}: {name} factor is {b[name]} but scoring_model says {want}")

        if windows and windows.get(r["severity"]) != r["remediation_window"]:
            problems.append(f"{rid}: remediation_window {r['remediation_window']} does not match scoring_model ({windows.get(r['severity'])})")
        if not (1 <= r["likelihood"] <= 5 and 1 <= r["impact"] <= 5):
            problems.append(f"{rid}: likelihood/impact must be 1-5")
        if not r["evidence"]:
            problems.append(f"{rid}: no evidence")
        for ev in r["evidence"]:
            if ev.get("source") not in EVIDENCE_SOURCES:
                problems.append(f"{rid}: unknown evidence source {ev.get('source')!r}")
            if ev.get("source") == "auth_logs" and ev.get("ref") not in anomaly_ids:
                problems.append(f"{rid}: evidence ref {ev.get('ref')} is not in the anomalies list")

    if problems and raise_on_error:
        raise ContractError(problems)
    return problems
