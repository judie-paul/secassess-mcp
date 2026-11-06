"""Likelihood, impact, risk scoring and ranking."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import config
from analysis import scoring
from analysis.impact import compute_impact
from analysis.likelihood import compute_likelihood
from api.schemas.anomalies import Anomaly
from api.schemas.assets import Asset, SecurityControls
from api.schemas.findings import Finding
from api.schemas.inventory import DataInventoryRecord

TS = datetime(2026, 11, 1, tzinfo=timezone.utc)


def make_asset(**overrides):
    data = dict(
        asset_id="a-1", organization_id="org-x", name="test", asset_type="s3_bucket", service="S3",
        region="af-south-1", environment="production", exposure="public", data_sensitivity="pii",
        business_criticality="critical", owner="team", description="d", discovered_at=TS,
        security_controls=SecurityControls(encryption_at_rest=False, logging_enabled=True, mfa_enforced=True),
    )
    data.update(overrides)
    return Asset(**data)


def make_finding(**overrides):
    data = dict(
        finding_id="F-1", organization_id="org-x", asset_id="a-1", service="S3", title="t", description="d",
        category="network_exposure", severity="critical", exposure="public", exploitability="trivial",
        detection_source="test", detected_at=TS, status="open",
    )
    data.update(overrides)
    return Finding(**data)


def make_anomaly(confidence="high", n=1):
    return Anomaly(
        anomaly_id=f"A-{n}", type="excessive_failed_logins", organization_id="org-x", user="u",
        asset_id="a-1", country="XX", timestamp=TS, detail="d", confidence=confidence,
        supporting_event_ids=["E1"],
    )


def inventory(count=2_000_000, pii=True, financial=True):
    return DataInventoryRecord(
        asset_id="a-1", organization_id="org-x", data_classification="Restricted", data_categories=["x"],
        contains_pii=pii, contains_financial_data=financial, record_count=count, storage_location="s3://x",
    )


def factor(component, name):
    return next(f for f in component.factors if f.factor == name)


# --- rounding and bands ------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [(1.0, 1), (2.49, 2), (2.5, 3), (2.4999999999999996, 3), (3.49, 3), (4.5, 5), (5.0, 5), (0.2, 1)])
def test_round_half_up(raw, expected):
    assert scoring.round_score(raw) == expected


@pytest.mark.parametrize("score,band", [(1, "low"), (4, "low"), (5, "medium"), (9, "medium"), (10, "high"),
                                        (16, "high"), (17, "critical"), (25, "critical")])
def test_risk_bands(score, band):
    assert scoring.risk_band(score) == band


def test_risk_score_is_product_and_validates_range():
    assert scoring.risk_score(4, 5) == 20
    with pytest.raises(ValueError):
        scoring.risk_score(0, 5)


# --- likelihood (contract rule) ----------------------------------------------------


@pytest.mark.parametrize(
    "exposure,anomalous,expected",
    [("public", True, 5), ("public", False, 4), ("internal", True, 3), ("internal", False, 2)],
)
def test_likelihood_rule_matches_contract_examples(exposure, anomalous, expected):
    # contracts/report_data.example.json: R-001 public+anomalous=5, R-002 public=4,
    # R-003 internal+anomalous=3, R-004 internal=2
    detail = compute_likelihood(exposure, anomalous)
    assert detail.score == expected
    assert detail.rule == "public = 4, internal = 2; +1 if anomalous access; max 5"


def test_likelihood_is_capped(monkeypatch):
    monkeypatch.setitem(config.LIKELIHOOD_BY_EXPOSURE, "public", 5)
    assert compute_likelihood("public", True).score == config.LIKELIHOOD_MAX


# --- impact ----------------------------------------------------------------------


def test_impact_weighted_formula():
    result = compute_impact(make_asset(), inventory())
    scores = {f.factor: f.score for f in result.factors}
    assert scores == {"data_sensitivity": 5, "business_criticality": 5, "affected_records": 5,
                      "financial_impact": 5, "operational_impact": 5}
    assert result.score == 5


def test_unknown_record_count_is_not_zero():
    result = compute_impact(make_asset(), inventory(count=None))
    records = factor(result, "affected_records")
    assert records.score == config.NEUTRAL_FACTOR_SCORES["affected_records"]
    assert records.score > config.RECORD_COUNT_THRESHOLDS[0][1]
    assert records.confidence == "low"
    assert "not treated as zero" in records.basis


@pytest.mark.parametrize("count,expected", [(0, 1), (999, 1), (1_000, 2), (50_000, 3), (100_000, 4), (1_000_000, 5)])
def test_record_count_bands(count, expected):
    assert factor(compute_impact(make_asset(), inventory(count=count)), "affected_records").score == expected


def test_low_value_asset_has_low_impact():
    asset = make_asset(data_sensitivity="public", business_criticality="low", environment="development")
    result = compute_impact(asset, inventory(count=10, pii=False, financial=False))
    assert result.score == 1


def test_inventory_raises_sensitivity():
    asset = make_asset(data_sensitivity="internal")
    result = compute_impact(asset, inventory(pii=True, financial=False))
    assert factor(result, "data_sensitivity").score == config.SENSITIVITY_SCORES["pii"]


# --- weighted risk score ------------------------------------------------------------


def test_scoring_model_block_matches_contract():
    import json
    from tests.conftest import CONTRACT

    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))["scoring_model"]
    assert scoring.scoring_model().model_dump() == contract


def test_weighted_score_matches_example_report():
    # report_data.example.json: critical, public, PII, suspicious activity -> 60.0
    breakdown = scoring.score_breakdown("critical", "public", "pii", True)
    assert breakdown.model_dump() == {"severity": 10, "exposure": 2.0, "data_sensitivity": 2.0, "activity": 1.5}
    assert scoring.weighted_risk_score(breakdown) == 60.0
    assert scoring.weighted_risk_score(scoring.score_breakdown("critical", "internal", "internal", True)) == 18.0


def test_weighted_score_uses_config_weights():
    breakdown = scoring.score_breakdown("low", "internal", "health", False)
    expected = (
        config.SEVERITY_WEIGHTS["low"]
        * config.EXPOSURE_WEIGHTS["internal"]
        * config.SENSITIVITY_WEIGHTS["health"]
        * config.ACTIVITY_WEIGHTS["normal"]
    )
    assert scoring.weighted_risk_score(breakdown) == round(expected, config.RISK_SCORE_DECIMALS)


# --- ranking on the demo data -------------------------------------------------------


def test_every_active_finding_is_scored_in_rank_order(services):
    scored = services.risks.scored_findings("org-001")
    active = [f for f in services.repo.findings_for("org-001") if f.status in config.ACTIVE_FINDING_STATUSES]
    assert sorted(s.finding_id for s in scored) == sorted(f.finding_id for f in active)
    keys = [
        (-s.risk.score, -s.detail.likelihood_x_impact, -s.risk.impact, -s.risk.likelihood, s.finding_id)
        for s in scored
    ]
    assert keys == sorted(keys)


def test_score_breakdown_is_consistent(services):
    for item in services.risks.scored_findings("org-001"):
        risk, detail = item.risk, item.detail
        assert risk.score == scoring.weighted_risk_score(risk.score_breakdown)
        assert risk.likelihood == detail.likelihood.score and risk.impact == detail.impact.score
        assert risk.likelihood == compute_likelihood(risk.exposure, risk.anomalous_access).score
        assert detail.likelihood_x_impact == risk.likelihood * risk.impact
        assert detail.likelihood_x_impact_band == scoring.risk_band(detail.likelihood_x_impact)
        assert risk.remediation_window == config.REMEDIATION_WINDOW_BY_SEVERITY[risk.severity]
        impact = detail.impact
        assert {f.factor: f.weight for f in impact.factors} == config.IMPACT_WEIGHTS
        assert impact.raw_score == pytest.approx(sum(f.score * f.weight for f in impact.factors))
        assert impact.score == scoring.round_score(impact.raw_score)


def test_ranked_risks_are_one_per_asset_with_sequential_ids(services):
    ranked = services.risks.ranked_risks("org-001")
    assert len({r.asset_id for r in ranked}) == len(ranked)
    assert [r.risk.rank for r in ranked] == list(range(1, len(ranked) + 1))
    assert [r.risk.risk_id for r in ranked] == [f"R-{i:03d}" for i in range(1, len(ranked) + 1)]
    assert all(r.detail.likelihood_x_impact >= config.MIN_QUALIFYING_LIKELIHOOD_IMPACT for r in ranked)


def test_ranked_risk_is_the_assets_best_finding(services):
    scored = services.risks.scored_findings("org-001")
    for item in services.risks.ranked_risks("org-001"):
        best = next(
            s for s in scored
            if s.asset_id == item.asset_id
            and s.detail.likelihood_x_impact >= config.MIN_QUALIFYING_LIKELIHOOD_IMPACT
        )
        assert best.finding_id == item.finding_id


def test_inactive_findings_are_not_scored(services):
    scored = {s.finding_id for s in services.risks.scored_findings("org-001")}
    assert "FND-0005" not in scored  # accepted risk
    assert "FND-0010" not in scored  # resolved


def test_well_controlled_assets_rank_below_exposed_sensitive_ones(services):
    ranks = {r.asset_id: r.risk.rank for r in services.risks.ranked_risks("org-001")}
    assert ranks["a-rds-001"] == 1
    assert ranks["a-s3-001"] < ranks.get("a-rds-002", 999)
    assert "a-kms-002" not in ranks  # no findings at all


def test_scoring_is_reproducible(services, reports_dir):
    from api.dependencies import Services

    first = [s.model_dump() for s in services.risks.scored_findings("org-001")]
    second = [s.model_dump() for s in Services(reports_dir=reports_dir).risks.scored_findings("org-001")]
    assert first == second
