"""Assessment reports: exact contracts/report_data.example.json format, contract validation,
deck generation, annotation validation and reproducibility."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import config
from api.dependencies import Services
from api.schemas.reports import AssessmentRequest
from reporting import build_report, validate_contract
from tests.conftest import ORG, SMALL_ORG

BASE = f"/organizations/{ORG}/assessments"
EXAMPLE_PATH = Path(__file__).resolve().parent.parent / "contracts" / "report_data.example.json"
# The agreed backend/reporting data contract (see contracts/HANDOFF.md).
EXAMPLE = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8")) if EXAMPLE_PATH.exists() else None
requires_example = pytest.mark.skipif(EXAMPLE is None, reason="contracts/report_data.example.json not present")

# Objects whose keys are data (service names), not schema: values must be integers.
DATA_KEYED_COUNTS = {"$.findings_by_service"}
# Objects whose keys are data (anomaly types): every value must match the example's first value.
DATA_KEYED_OBJECTS = {"$.anomaly_types"}
# Fields that may legitimately be null in our output even where the example has a value.
NULLABLE = {"record_count", "business_impact", "remediation", "asset_id", "country"}


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def assert_same_shape(actual, example, path="$", key=None):
    """Same keys in the same order and the same JSON types as the example, at every level."""
    if example is None or actual is None:
        if actual is None and example is not None:
            assert key in NULLABLE, f"{path} is null but the example has a value"
        return
    assert json_type(actual) == json_type(example), f"{path}: {json_type(actual)} != {json_type(example)}"
    if isinstance(example, dict):
        if path in DATA_KEYED_COUNTS:
            assert all(isinstance(k, str) and isinstance(v, int) for k, v in actual.items()), path
            return
        if path in DATA_KEYED_OBJECTS:
            template = next(iter(example.values()))
            for name, value in actual.items():
                assert_same_shape(value, template, f"{path}.{name}", name)
            return
        assert list(actual) == list(example), f"{path}: keys {list(actual)} != {list(example)}"
        for name in example:
            assert_same_shape(actual[name], example[name], f"{path}.{name}", name)
    elif isinstance(example, list) and example:
        # Every item must match the first example item; evidence items have one shared shape.
        for index, item in enumerate(actual):
            assert_same_shape(item, example[0], f"{path}[{index}]", key)


def annotations_for(client, limit=5):
    risks = client.get(f"/organizations/{ORG}/risks", params={"limit": limit}).json()["items"]
    return [
        {"risk_id": r["risk_id"], "business_impact": f"Impact of {r['title']}", "remediation": "Fix the configuration."}
        for r in risks
    ]


# --- exact format and contract --------------------------------------------------------


@requires_example
def test_example_file_matches_itself():
    assert_same_shape(EXAMPLE, EXAMPLE)
    assert validate_contract(EXAMPLE, raise_on_error=False) == []


@requires_example
@pytest.mark.parametrize("limit", [5, 6, 7])
def test_complete_report_matches_example_format(client, limit):
    response = client.post(BASE, json={"top_risks_limit": limit, "annotations": annotations_for(client, limit)})
    assert response.status_code == 201
    report = response.json()
    assert_same_shape(report, EXAMPLE)
    assert len(report["top_risks"]) == limit
    assert response.headers["X-Report-Status"] == "complete"


@requires_example
def test_draft_report_matches_example_format_with_null_ai_fields(client):
    response = client.post(BASE)
    report = response.json()
    assert_same_shape(report, EXAMPLE)
    assert response.headers["X-Report-Status"] == "draft"
    assert len(report["top_risks"]) == config.DEFAULT_TOP_RISKS
    for risk in report["top_risks"]:
        assert (risk["business_impact"], risk["remediation"]) == (None, None)


@pytest.mark.parametrize("org", [ORG, SMALL_ORG])
def test_report_passes_reporting_contract_validation(client, org):
    risks = client.get(f"/organizations/{org}/risks").json()["items"]
    notes = [{"risk_id": r["risk_id"], "business_impact": "x", "remediation": "y"} for r in risks]
    report = client.post(f"/organizations/{org}/assessments", json={"annotations": notes}).json()
    assert validate_contract(report, raise_on_error=False) == []


def test_reporting_builds_a_deck_from_backend_data(client, tmp_path):
    report = client.post(BASE, json={"annotations": annotations_for(client)}).json()
    path = Path(build_report(report, {}, out_dir=str(tmp_path), fmt="pptx"))
    assert path.exists() and path.suffix == ".pptx" and path.stat().st_size > 0


@requires_example
def test_scoring_model_and_anomaly_types_blocks(client):
    report = client.post(BASE).json()
    assert report["scoring_model"] == EXAMPLE["scoring_model"]
    assert list(report["anomaly_types"]) == list(config.ANOMALY_TYPES)
    for name, info in EXAMPLE["anomaly_types"].items():
        assert report["anomaly_types"][name] == info
    assert {a["type"] for a in report["anomalies"]} <= set(report["anomaly_types"])


def test_report_values_follow_contract_conventions(client):
    report = client.post(BASE).json()
    assert report["schema_version"] == "1.0"
    assert report["generated_at"] == "2026-11-06T18:00:00Z"
    assert report["organisation"] == "Savanna Ridge Financial Ltd"
    assert list(report["summary"]["by_severity"]) == ["critical", "high", "medium", "low"]
    model = report["scoring_model"]
    for risk in report["top_risks"]:
        assert risk["risk_id"] == f"R-{risk['rank']:03d}"
        b = risk["score_breakdown"]
        assert risk["score"] == round(b["severity"] * b["exposure"] * b["data_sensitivity"] * b["activity"], 2)
        assert risk["data_sensitivity"] in model["factors"]["data_sensitivity"]
        assert risk["remediation_window"] == model["remediation_windows"][risk["severity"]]
        assert {e["source"] for e in risk["evidence"]} <= {"findings", "data_inventory", "auth_logs"}
    scores = [r["score"] for r in report["top_risks"]]
    assert scores == sorted(scores, reverse=True)
    assert len({r["asset_id"] for r in report["top_risks"]}) == len(report["top_risks"])
    stamps = [a["timestamp"] for a in report["anomalies"]]
    assert stamps == sorted(stamps, reverse=True)
    assert all(len(a["country"]) == 2 for a in report["anomalies"])


def test_top_risk_one_is_the_exposed_customer_database(client):
    top = client.post(BASE).json()["top_risks"][0]
    assert top["asset_id"] == "a-rds-001"
    assert top["data_sensitivity"] == "PII"
    assert top["score"] == 60.0
    assert top["score_breakdown"] == {"severity": 10, "exposure": 2.0, "data_sensitivity": 2.0, "activity": 1.5}
    assert (top["likelihood"], top["anomalous_access"], top["remediation_window"]) == (5, True, "0-30")


def test_report_summary_and_matrix_match_backend(client):
    report = client.post(BASE).json()
    summary = client.get(f"/organizations/{ORG}/summary").json()
    for key in ("schema_version", "generated_at", "organisation", "scoring_model", "anomaly_types", "summary",
                "findings_by_service", "risk_matrix"):
        assert report[key] == summary[key]
    total = report["summary"]["total_findings"]
    assert sum(report["findings_by_service"].values()) == total
    assert sum(c["count"] for c in report["risk_matrix"]) == total  # every finding, incl. resolved
    cells = [(c["impact"], c["likelihood"]) for c in report["risk_matrix"]]
    assert cells == sorted(cells, reverse=True)  # impact, then likelihood, highest first
    assert len(report["anomalies"]) == report["summary"]["anomalies_detected"]


def test_report_matches_mcp_tool_outputs(client):
    report = client.post(BASE).json()
    assert report["top_risks"] == client.get(f"/organizations/{ORG}/risks").json()["items"]
    assert report["anomalies"] == client.get(f"/organizations/{ORG}/anomalies").json()["items"]


# --- annotations --------------------------------------------------------------------


@pytest.mark.parametrize("field,value", [("score", 1), ("remediation_window", "0-30"), ("likelihood", 5)])
def test_annotations_cannot_set_backend_fields(client, field, value):
    notes = annotations_for(client)
    notes[0][field] = value
    assert client.post(BASE, json={"annotations": notes}).status_code == 422


def test_annotations_do_not_change_numbers(client):
    draft = client.post(BASE).json()
    complete = client.post(BASE, json={"annotations": annotations_for(client)}).json()
    for before, after in zip(draft["top_risks"], complete["top_risks"]):
        for key in ("rank", "risk_id", "score", "score_breakdown", "likelihood", "impact", "severity",
                    "evidence", "remediation_window"):
            assert before[key] == after[key]


def test_remediation_windows_follow_severity(client):
    risks = client.get(f"/organizations/{ORG}/risks", params={"limit": 7}).json()["items"]
    assert {r["remediation_window"] for r in risks} <= set(config.REMEDIATION_WINDOWS)
    for risk in risks:
        assert risk["remediation_window"] == config.REMEDIATION_WINDOW_BY_SEVERITY[risk["severity"]]


def test_annotation_for_unknown_risk_rejected(client):
    notes = annotations_for(client)
    notes[0]["risk_id"] = "R-999"
    response = client.post(BASE, json={"annotations": notes})
    assert response.status_code == 422
    assert "R-999" in response.json()["error"]["message"]


def test_duplicate_and_blank_annotations_rejected(client):
    notes = annotations_for(client)
    assert client.post(BASE, json={"annotations": notes + notes[:1]}).status_code == 422
    notes[0]["remediation"] = "   "
    assert client.post(BASE, json={"annotations": notes}).status_code == 422


def test_partial_annotations_leave_report_in_draft(client):
    response = client.post(BASE, json={"annotations": annotations_for(client)[:2]})
    assert response.headers["X-Report-Status"] == "draft"
    filled = [r["business_impact"] is not None for r in response.json()["top_risks"]]
    assert filled == [True, True, False, False, False]


def test_report_limit_validation(client):
    assert client.post(BASE, json={"top_risks_limit": 8}).status_code == 422
    assert client.post(BASE, json={"top_risks_limit": 4}).status_code == 422


# --- storage ------------------------------------------------------------------------


def test_get_stored_report(client):
    created = client.post(BASE, json={"annotations": annotations_for(client)})
    report_id = created.headers["X-Report-Id"]
    assert created.headers["Location"] == f"{BASE}/{report_id}"
    fetched = client.get(f"{BASE}/{report_id}")
    assert fetched.status_code == 200
    assert fetched.json() == created.json()


@pytest.mark.parametrize("report_id", ["RPT-000000000000", "..%2F..%2Fconfig", "not-a-report"])
def test_get_missing_or_malformed_report(client, report_id):
    assert client.get(f"{BASE}/{report_id}").status_code == 404


def test_report_not_visible_to_other_org(client):
    report_id = client.post(BASE).headers["X-Report-Id"]
    assert client.get(f"/organizations/{SMALL_ORG}/assessments/{report_id}").status_code == 404


def test_small_org_report_explains_insufficient_risks(client):
    response = client.post(f"/organizations/{SMALL_ORG}/assessments")
    report = response.json()
    if EXAMPLE is not None:
        assert_same_shape(report, EXAMPLE)
    assert len(report["top_risks"]) < config.MIN_TOP_RISKS
    assert "Insufficient qualifying risks" in response.headers["X-Top-Risks-Note"]


def test_report_numbers_are_reproducible(reports_dir, tmp_path):
    request = AssessmentRequest()
    first = Services(reports_dir=reports_dir).reports.build(ORG, request)
    second = Services(reports_dir=tmp_path / "other").reports.build(ORG, request)
    assert first.report.model_dump(mode="json") == second.report.model_dump(mode="json")
    assert first.report_id == second.report_id
