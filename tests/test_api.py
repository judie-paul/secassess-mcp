"""FastAPI endpoints: happy paths, filtering, pagination and errors."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import config
from api.main import create_app
from tests.conftest import ORG, SMALL_ORG

BASE = f"/organizations/{ORG}"


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    "path",
    ["/summary", "/findings", "/assets/a-rds-001", "/auth-logs", "/risks", "/data-inventory", "/anomalies"],
)
def test_unknown_organization_returns_404(client, path):
    response = client.get(f"/organizations/org-999{path}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


# --- summary ---------------------------------------------------------------------


def test_summary(client):
    body = client.get(f"{BASE}/summary").json()
    assert body["organisation"] == "Savanna Ridge Financial Ltd"
    assert body["schema_version"] == config.SCHEMA_VERSION
    assert body["generated_at"] == "2026-11-06T18:00:00Z"
    summary = body["summary"]
    assert summary["total_assets"] == 23
    assert summary["total_findings"] == sum(summary["by_severity"].values())
    assert list(summary["by_severity"]) == list(config.ALLOWED_SEVERITIES)
    assert 0 < summary["sensitive_assets_exposed"] <= summary["sensitive_assets"]
    assert summary["anomalies_detected"] == 9
    assert sum(body["findings_by_service"].values()) == summary["total_findings"]
    counts = list(body["findings_by_service"].values())
    assert counts == sorted(counts, reverse=True)
    assert sum(c["count"] for c in body["risk_matrix"]) == summary["total_findings"]
    assert list(body)[:5] == ["organization_id", "schema_version", "generated_at", "organisation", "scoring_model"]
    assert body["statistics"]["qualifying_risks"] >= config.MIN_TOP_RISKS


# --- findings --------------------------------------------------------------------


def test_findings_default_page(client):
    body = client.get(f"{BASE}/findings").json()
    assert body["total"] == 41 and body["offset"] == 0
    assert len(body["items"]) == min(41, config.DEFAULT_PAGE_LIMIT)
    severities = [config.ALLOWED_SEVERITIES.index(f["severity"]) for f in body["items"]]
    assert severities == sorted(severities)


def test_findings_combined_filters(client):
    body = client.get(f"{BASE}/findings", params={"severity": "critical", "service": "RDS", "status": "open"}).json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "RDS instance publicly accessible"


def test_findings_pagination_is_consistent(client):
    full = client.get(f"{BASE}/findings", params={"limit": 200}).json()["items"]
    page1 = client.get(f"{BASE}/findings", params={"limit": 10, "offset": 0}).json()
    page2 = client.get(f"{BASE}/findings", params={"limit": 10, "offset": 10}).json()
    assert page1["items"] + page2["items"] == full[:20]
    assert client.get(f"{BASE}/findings", params={"offset": 500}).json()["items"] == []


@pytest.mark.parametrize("params", [{"severity": "urgent"}, {"service": "GCS"}, {"limit": 0},
                                    {"limit": config.MAX_PAGE_LIMIT + 1}, {"offset": -1}])
def test_findings_invalid_parameters(client, params):
    response = client.get(f"{BASE}/findings", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


# --- assets ----------------------------------------------------------------------


def test_get_asset_detail(client):
    body = client.get(f"{BASE}/assets/a-rds-001").json()
    assert body["service"] == "RDS" and body["exposure"] == "public"
    assert body["record_count"] == 1_284_000
    assert {f["asset_id"] for f in body["related_findings"]} == {"a-rds-001"}
    assert len(body["related_anomalies"]) == 2  # new country + unusual access
    assert "network_restricted" in body["security_info"]["failed_controls"]


def test_get_asset_unknown_record_count_is_null(client):
    assert client.get(f"{BASE}/assets/a-rds-003").json()["record_count"] is None


def test_get_asset_not_found(client):
    response = client.get(f"{BASE}/assets/a-missing")
    assert response.status_code == 404
    assert "a-missing" in response.json()["error"]["message"]


def test_asset_from_another_org_is_not_visible(client):
    assert client.get(f"{BASE}/assets/b-s3-001").status_code == 404


# --- auth logs -------------------------------------------------------------------


def test_auth_logs_multiple_filters(client):
    params = {"username": "ops-admin", "outcome": "failure", "country": "Netherlands", "asset_id": "a-iam-001"}
    body = client.get(f"{BASE}/auth-logs", params=params).json()
    assert body["total"] == 8
    assert all(e["source_ip"] == "203.0.113.45" for e in body["items"])


def test_auth_logs_country_accepts_iso_code(client):
    by_code = client.get(f"{BASE}/auth-logs", params={"country": "NL", "limit": 200}).json()
    by_name = client.get(f"{BASE}/auth-logs", params={"country": "netherlands", "limit": 200}).json()
    assert by_code["total"] == by_name["total"] > 0


def test_auth_logs_time_window_and_order(client):
    params = {"start_time": "2026-11-04T00:00:00Z", "end_time": "2026-11-05T23:59:59Z", "limit": 200}
    items = client.get(f"{BASE}/auth-logs", params=params).json()["items"]
    assert items
    stamps = [e["timestamp"] for e in items]
    assert stamps == sorted(stamps, reverse=True)
    assert all("2026-11-04" <= s[:10] <= "2026-11-05" for s in stamps)


def test_auth_logs_inverted_window_rejected(client):
    params = {"start_time": "2026-11-05T00:00:00Z", "end_time": "2026-11-01T00:00:00Z"}
    response = client.get(f"{BASE}/auth-logs", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


# --- risks -----------------------------------------------------------------------


def test_top_risks_default_five(client):
    body = client.get(f"{BASE}/risks").json()
    assert body["returned"] == 5 and body["sufficient_risks"] is True and body["message"] is None
    assert [r["rank"] for r in body["items"]] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("limit", [5, 6, 7])
def test_top_risks_limits(client, limit):
    assert client.get(f"{BASE}/risks", params={"limit": limit}).json()["returned"] == limit


@pytest.mark.parametrize("limit", [4, 8, 0])
def test_top_risks_limit_out_of_range(client, limit):
    assert client.get(f"{BASE}/risks", params={"limit": limit}).status_code == 422


def test_top_risks_insufficient_returns_all_with_explanation(client):
    body = client.get(f"/organizations/{SMALL_ORG}/risks").json()
    assert body["sufficient_risks"] is False
    assert 0 < body["returned"] == body["qualifying_risks"] < config.MIN_TOP_RISKS
    assert "Insufficient qualifying risks" in body["message"]


def test_risk_evidence_references_exist(client):
    from api.data_access.json_repository import JsonRepository

    repo = JsonRepository()
    known = {
        "findings": {f.finding_id for f in repo.findings()},
        "data_inventory": {r.asset_id for r in repo.data_inventory()},
        "auth_logs": {a["anomaly_id"] for a in client.get(f"{BASE}/anomalies").json()["items"]},
    }
    for risk in client.get(f"{BASE}/risks", params={"limit": 7}).json()["items"]:
        assert risk["evidence"] and risk["evidence"][0]["source"] == "findings"
        for ref in risk["evidence"]:
            assert ref["ref"] in known[ref["source"]], ref
            assert ref["detail"]


def test_top_risks_include_scoring_details(client):
    body = client.get(f"{BASE}/risks").json()
    assert set(body["scoring_details"]) == {r["risk_id"] for r in body["items"]}
    for risk in body["items"]:
        detail = body["scoring_details"][risk["risk_id"]]
        assert detail["likelihood"]["score"] == risk["likelihood"]
        assert detail["impact"]["score"] == risk["impact"]
        assert detail["likelihood_x_impact"] == risk["likelihood"] * risk["impact"]
        assert risk["business_impact"] is None and risk["remediation"] is None
        assert risk["remediation_window"] == config.REMEDIATION_WINDOW_BY_SEVERITY[risk["severity"]]


# --- data inventory ----------------------------------------------------------------


def test_data_inventory_filters(client):
    all_items = client.get(f"{BASE}/data-inventory").json()
    pii_fin = client.get(f"{BASE}/data-inventory", params={"contains_pii": True, "contains_financial_data": True}).json()
    assert pii_fin and all(i["contains_pii"] and i["contains_financial_data"] for i in pii_fin)
    assert len(pii_fin) < len(all_items)
    public = client.get(f"{BASE}/data-inventory", params={"sensitivity": "public"}).json()
    assert [i["asset_id"] for i in public] == ["a-s3-002"]
    one = client.get(f"{BASE}/data-inventory", params={"asset_id": "a-s3-003"}).json()
    assert one[0]["record_count"] is None and one[0]["record_count_note"]


def test_data_inventory_unknown_asset(client):
    assert client.get(f"{BASE}/data-inventory", params={"asset_id": "nope"}).status_code == 404


# --- anomalies -------------------------------------------------------------------


def test_anomalies_endpoint(client):
    body = client.get(f"{BASE}/anomalies").json()
    assert body["total"] == 9
    assert "not confirmed malicious" in body["note"]
    assert set(body["evidence"]) == {a["anomaly_id"] for a in body["items"]}
    for anomaly in body["items"]:
        assert list(anomaly) == ["anomaly_id", "type", "user", "asset_id", "country", "timestamp", "detail"]
        assert body["evidence"][anomaly["anomaly_id"]]["supporting_event_ids"]


def test_anomalies_filters(client):
    by_type = client.get(f"{BASE}/anomalies", params={"anomaly_type": "excessive_failed_logins"}).json()
    assert by_type["total"] == 3
    by_asset = client.get(f"{BASE}/anomalies", params={"asset_id": "a-rds-001"}).json()
    assert {a["type"] for a in by_asset["items"]} == {"new_country", "unusual_data_access"}
    recent = client.get(f"{BASE}/anomalies", params={"start_time": "2026-11-01T00:00:00Z"}).json()
    assert all(a["timestamp"] >= "2026-11-01" for a in recent["items"]) and recent["total"] == 3


def test_anomalies_invalid_type(client):
    assert client.get(f"{BASE}/anomalies", params={"anomaly_type": "alien"}).status_code == 422


# --- data errors surface as 500 with a clear message ---------------------------------


def test_corrupt_data_file_returns_500(data_copy, tmp_path):
    (data_copy / "findings.json").write_text("{broken", encoding="utf-8")
    client = TestClient(create_app(data_dir=data_copy, reports_dir=tmp_path / "r"))
    response = client.get(f"{BASE}/findings")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "data_error",
        "message": "Invalid JSON in findings.json: line 1, column 2: Expecting property name enclosed in double quotes",
    }
