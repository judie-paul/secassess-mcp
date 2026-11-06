"""Data loading, integrity and fixed-reference-time behaviour."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import config
from api.data_access.json_repository import JsonRepository
from api.errors import DataLoadError
from data import generate_demo_data

ROOT = Path(__file__).resolve().parent.parent


def test_all_datasets_load_and_validate():
    repo = JsonRepository()
    assert len(repo.organizations()) >= 1
    assert len(repo.assets_for("org-001")) >= 20
    assert len(repo.findings()) >= 30
    assert len(repo.auth_logs()) >= 100
    assert repo.data_inventory()
    assert repo.anomaly_snapshot()["anomalies"]


def test_dataset_is_referentially_consistent():
    assert JsonRepository().integrity_errors() == []


def test_dataset_covers_required_variety():
    repo = JsonRepository()
    assets = repo.assets_for("org-001")
    assert {"S3", "IAM", "EC2", "RDS", "KMS", "Lambda", "CloudTrail"} <= {a.service for a in assets}
    assert {a.exposure for a in assets} == set(config.ALLOWED_EXPOSURES)
    assert {f.severity for f in repo.findings()} == set(config.ALLOWED_SEVERITIES)
    assert any(r.record_count is None for r in repo.data_inventory()), "need unknown record counts"
    events = repo.auth_logs()
    assert {"success", "failure"} == {e.outcome for e in events}
    assert {"human", "admin", "service"} <= {e.user_type for e in events}
    assert len({e.country for e in events}) >= 5


def test_auth_logs_span_historical_window_before_reference_time():
    events = JsonRepository().auth_logs_for("org-001")
    first, last = min(e.timestamp for e in events), max(e.timestamp for e in events)
    assert last <= config.REFERENCE_TIME
    assert (config.REFERENCE_TIME - first).days >= config.HISTORICAL_WINDOW_DAYS


def test_all_timestamps_are_utc_and_not_after_reference():
    repo = JsonRepository()
    stamps = [e.timestamp for e in repo.auth_logs()] + [f.detected_at for f in repo.findings()]
    stamps += [a.discovered_at for a in repo.assets()]
    for ts in stamps:
        assert ts.tzinfo is not None and ts.utcoffset().total_seconds() == 0
        assert ts <= config.REFERENCE_TIME


def test_missing_file_raises_data_error(data_copy):
    (data_copy / "assets.json").unlink()
    with pytest.raises(DataLoadError, match="not found"):
        JsonRepository(data_copy).assets()


def test_invalid_json_raises_data_error(data_copy):
    (data_copy / "findings.json").write_text("[{ not json", encoding="utf-8")
    with pytest.raises(DataLoadError, match="Invalid JSON in findings.json"):
        JsonRepository(data_copy).findings()


def test_schema_violation_raises_data_error(data_copy):
    path = data_copy / "findings.json"
    findings = json.loads(path.read_text(encoding="utf-8"))
    findings[0]["severity"] = "catastrophic"
    path.write_text(json.dumps(findings), encoding="utf-8")
    with pytest.raises(DataLoadError, match="failed validation"):
        JsonRepository(data_copy).findings()


def test_non_array_file_raises_data_error(data_copy):
    (data_copy / "assets.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DataLoadError, match="JSON array"):
        JsonRepository(data_copy).assets()


def test_integrity_check_detects_dangling_reference(data_copy):
    path = data_copy / "findings.json"
    findings = json.loads(path.read_text(encoding="utf-8"))
    findings[0]["asset_id"] = "a-does-not-exist"
    path.write_text(json.dumps(findings), encoding="utf-8")
    errors = JsonRepository(data_copy).integrity_errors()
    assert any("unknown asset a-does-not-exist" in e for e in errors)


def test_generator_is_deterministic_and_matches_committed_data(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    generate_demo_data.main(first)
    generate_demo_data.main(second)
    for name in config.DATA_FILES.values():
        generated = (first / name).read_bytes()
        assert generated == (second / name).read_bytes(), f"{name} differs between runs"
        assert generated == (config.DATA_DIR / name).read_bytes(), f"{name} is stale; rerun the generator"


def test_reference_time_is_fixed():
    assert config.REFERENCE_TIME.isoformat() == "2026-11-06T18:00:00+00:00"
    assert config.report_timestamp() == config.REFERENCE_TIME


def test_no_wall_clock_in_analysis_or_data_code():
    """Only config.report_timestamp may read the clock (and only outside demo mode)."""
    offenders = []
    for path in [p for folder in ("api", "analysis", "data", "mcp_server") for p in (ROOT / folder).rglob("*.py")]:
        if path.name == "config.py":
            continue
        if re.search(r"datetime\.(now|utcnow|today)\(|time\.time\(", path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    assert offenders == []


def test_impact_weights_sum_to_one():
    assert round(sum(config.IMPACT_WEIGHTS.values()), 9) == 1.0
