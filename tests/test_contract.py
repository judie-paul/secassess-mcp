"""The contract check must catch data that contradicts itself."""

import pytest

from reporting.contract import ContractError, validate_contract


def test_example_contract_is_consistent(data):
    assert validate_contract(data) == []


def test_missing_key_is_reported(data):
    del data["anomaly_types"]
    with pytest.raises(ContractError, match="anomaly_types"):
        validate_contract(data)


def test_severity_counts_must_add_up(data):
    data["summary"]["by_severity"]["low"] += 1
    with pytest.raises(ContractError, match="by_severity"):
        validate_contract(data)


def test_service_counts_must_add_up(data):
    data["findings_by_service"]["S3"] -= 1
    with pytest.raises(ContractError, match="findings_by_service"):
        validate_contract(data)


def test_score_must_equal_its_breakdown(data):
    data["top_risks"][0]["score"] = 61.0
    with pytest.raises(ContractError, match="breakdown product"):
        validate_contract(data)


def test_factor_must_match_scoring_model(data):
    risk = data["top_risks"][1]
    risk["score_breakdown"]["exposure"] = 1.5
    risk["score"] = 30.0  # product still matches, but 1.5 is not the model's "public" value
    with pytest.raises(ContractError, match="exposure factor"):
        validate_contract(data)


def test_risks_must_be_sorted_by_score(data):
    risks = data["top_risks"]
    risks[0], risks[1] = risks[1], risks[0]
    risks[0]["rank"], risks[1]["rank"] = 1, 2
    with pytest.raises(ContractError, match="sorted"):
        validate_contract(data)


def test_evidence_must_point_at_a_real_anomaly(data):
    data["top_risks"][0]["evidence"][2]["ref"] = "A-9999"
    with pytest.raises(ContractError, match="A-9999"):
        validate_contract(data)


def test_unknown_anomaly_type_is_reported(data):
    data["anomalies"][0]["type"] = "brute_force"
    with pytest.raises(ContractError, match="brute_force"):
        validate_contract(data)


def test_remediation_window_must_follow_severity(data):
    data["top_risks"][0]["remediation_window"] = "61-90"
    with pytest.raises(ContractError, match="remediation_window"):
        validate_contract(data)
