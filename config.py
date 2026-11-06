"""Central configuration for the security assessment demo.

Every threshold, weight, mapping and magic value used by the analysis and
report code lives here. Analysis modules must read from this file rather than
hard-coding numbers, so the methodology can be tuned without code changes.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths and runtime settings
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SECURITY_DATA_DIR", BASE_DIR / "data"))
REPORTS_DIR = Path(os.environ.get("SECURITY_REPORTS_DIR", DATA_DIR / "reports"))
# Where the MCP generate_report tool writes PPTX/PDF decks (git-ignored).
REPORT_OUTPUT_DIR = Path(os.environ.get("SECURITY_REPORT_OUTPUT_DIR", BASE_DIR / "output"))

API_TITLE = "Security Assessment API"
API_VERSION = "1.0.0"

# Base URL and timeout used by the MCP server to reach the FastAPI backend.
BACKEND_URL = os.environ.get("SECURITY_API_URL", "http://127.0.0.1:8000")
BACKEND_TIMEOUT_SECONDS = float(os.environ.get("SECURITY_API_TIMEOUT", "15"))

DATA_FILES = {
    "organizations": "organizations.json",
    "assets": "assets.json",
    "findings": "findings.json",
    "auth_logs": "auth_logs.json",
    "data_inventory": "data_inventory.json",
    "anomalies": "anomalies.json",
}

# ---------------------------------------------------------------------------
# Reference time (all demo data, reports and tests are anchored to this)
# ---------------------------------------------------------------------------

REFERENCE_TIME = datetime(2026, 11, 6, 18, 0, 0, tzinfo=timezone.utc)

# How far back anomaly baselines and the demo dataset look.
HISTORICAL_WINDOW_DAYS = 90
# Extra days of data generated before the historical window so that the
# earliest events inside the window still have a baseline.
DATASET_LEAD_IN_DAYS = 30
# "Current" activity window used for the threat-activity likelihood factor;
# anomalies older than this (but inside the historical window) count as
# historical activity instead.
ASSESSMENT_WINDOW_DAYS = 30

DEFAULT_ASSESSMENT_END = REFERENCE_TIME
DEFAULT_ASSESSMENT_START = REFERENCE_TIME - timedelta(days=HISTORICAL_WINDOW_DAYS)
CURRENT_ACTIVITY_START = REFERENCE_TIME - timedelta(days=ASSESSMENT_WINDOW_DAYS)

# Demo reports are stamped with the reference time so they are reproducible.
# Set to False to stamp reports with the real clock in non-demo use.
USE_REFERENCE_TIME_FOR_REPORTS = True

# Seed for the demo data generator.
DEMO_DATA_SEED = 20261106

# ---------------------------------------------------------------------------
# Allowed vocabulary
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0"

# How data sensitivity is written in reports (contracts/report_data.example.json).
REPORT_SENSITIVITY_LABELS = {
    "pii": "PII",
    "financial": "financial",
    "health": "health",
    "internal": "internal",
    "public": "public",
}

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
ALLOWED_EXPOSURES = ("public", "internal")
ALLOWED_SENSITIVITIES = ("pii", "financial", "health", "internal", "public")
ALLOWED_CRITICALITIES = ("critical", "high", "medium", "low")
ALLOWED_ENVIRONMENTS = ("production", "staging", "development")
ALLOWED_FINDING_STATUSES = ("open", "in_progress", "resolved", "accepted_risk")
ALLOWED_AUTH_OUTCOMES = ("success", "failure")
ALLOWED_EXPLOITABILITY = ("none", "difficult", "conditional", "easy", "trivial")
ALLOWED_SERVICES = ("S3", "IAM", "EC2", "RDS", "KMS", "Lambda", "CloudTrail")
REMEDIATION_WINDOWS = ("0-30", "31-60", "61-90")

# Findings in these statuses contribute to risks.
ACTIVE_FINDING_STATUSES = ("open", "in_progress")
# Sensitivity levels that make an asset "sensitive" in summaries.
SENSITIVE_DATA_LEVELS = ("pii", "financial", "health")
# Exposure levels that count as "exposed" for sensitive-asset statistics.
EXPOSED_LEVELS = ("public",)

# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200

# ---------------------------------------------------------------------------
# Scoring model (contracts/report_data.example.json -> scoring_model).
# A risk's `score` is severity x exposure x data_sensitivity x activity
# (e.g. critical, public, PII, anomalous = 10 x 2.0 x 2.0 x 1.5 = 60.0) and risks
# are ranked by it. Bump SCORING_MODEL_VERSION whenever a weight or rule changes.
# ---------------------------------------------------------------------------

SCORING_MODEL_VERSION = "1.0"
SCORING_FORMULA = "severity * exposure * data_sensitivity * activity"

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}
EXPOSURE_WEIGHTS = {"public": 2.0, "internal": 1.0}
# Keyed by internal sensitivity name; reported under REPORT_SENSITIVITY_LABELS.
SENSITIVITY_WEIGHTS = {
    "pii": 2.0,
    "financial": 2.0,
    "health": 2.0,
    "internal": 1.2,
    "public": 1.0,
}
ACTIVITY_WEIGHTS = {"anomalous": 1.5, "normal": 1.0}

# Likelihood rule: base score by exposure, +1 if the asset had anomalous access, capped.
LIKELIHOOD_BY_EXPOSURE = {"public": 4, "internal": 2}
LIKELIHOOD_ANOMALOUS_BONUS = 1
LIKELIHOOD_MAX = 5

# Remediation window by finding severity. The backend assigns it; the AI does not.
REMEDIATION_WINDOW_BY_SEVERITY = {
    "critical": "0-30",
    "high": "31-60",
    "medium": "61-90",
    "low": "61-90",
}

# Active findings of these categories are evidence that the mapped control is
# missing, even if the asset inventory does not record the control state.
CONTROL_FINDING_CATEGORY_MAP = {
    "missing_mfa": "mfa_enforced",
    "weak_authentication": "mfa_enforced",
    "unencrypted_storage": "encryption_at_rest",
    "weak_encryption_in_transit": "encryption_in_transit",
    "logging_disabled": "logging_enabled",
    "excessive_permissions": "least_privilege",
    "key_rotation_disabled": "key_rotation",
    "stale_credentials": "key_rotation",
    "network_exposure": "network_restricted",
    "backup_disabled": "backup_enabled",
}

# ---------------------------------------------------------------------------
# Impact model (1-5 scale)
# ---------------------------------------------------------------------------

IMPACT_WEIGHTS = {
    "data_sensitivity": 0.30,
    "business_criticality": 0.25,
    "affected_records": 0.20,
    "financial_impact": 0.15,
    "operational_impact": 0.10,
}

IMPACT_CRITERIA = {
    "data_sensitivity": {
        1: "Public information",
        2: "Internal information",
        3: "Unknown classification",
        4: "Sensitive business information",
        5: "Regulated personal, health or financial data",
    },
    "business_criticality": {
        1: "Negligible business reliance",
        2: "Low criticality",
        3: "Medium criticality",
        4: "High criticality",
        5: "Business-critical",
    },
    "affected_records": {
        1: "Fewer than 1,000 records",
        2: "1,000 - 9,999 records",
        3: "10,000 - 99,999 records (or unknown)",
        4: "100,000 - 999,999 records",
        5: "1,000,000 or more records",
    },
    "financial_impact": {
        1: "No direct financial consequence",
        2: "Minor financial consequence",
        3: "Moderate or unknown financial consequence",
        4: "Regulatory fines or notification costs likely",
        5: "Direct financial loss or fraud possible",
    },
    "operational_impact": {
        1: "Development system",
        2: "Staging or non-essential system",
        3: "Production supporting system",
        4: "Production system",
        5: "Business-critical production system",
    },
}

SENSITIVITY_SCORES = {"public": 1, "internal": 2, "pii": 5, "financial": 5, "health": 5}
CRITICALITY_SCORES = {"low": 2, "medium": 3, "high": 4, "critical": 5}
# (minimum record count, score); highest matching minimum wins.
RECORD_COUNT_THRESHOLDS = ((0, 1), (1_000, 2), (10_000, 3), (100_000, 4), (1_000_000, 5))
# Financial impact is derived from the data the asset holds.
FINANCIAL_IMPACT_SCORES = {
    "financial_data": 5,
    "pii": 4,
    "health": 4,
    "internal": 2,
    "public": 1,
}
OPERATIONAL_IMPACT_BY_ENVIRONMENT = {"development": 1, "staging": 2, "production": 4}
# Production assets with these criticalities get the adjustment below (capped at 5).
OPERATIONAL_CRITICALITY_ADJUSTMENT = {"critical": 1, "high": 0, "medium": -1, "low": -1}

# ---------------------------------------------------------------------------
# Unknown / missing evidence handling
# ---------------------------------------------------------------------------
# Missing evidence never scores 1 (which would claim "safe") or 5 (which would
# claim "worst case"). It gets a documented neutral value and the factor is
# flagged as low confidence in the score breakdown.

NEUTRAL_FACTOR_SCORES = {
    "data_sensitivity": 3,
    "business_criticality": 3,
    "affected_records": 3,
    "financial_impact": 3,
    "operational_impact": 3,
}

# Factor confidence labels.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
# Overall score confidence is "low" when at least this many factors are
# low-confidence, otherwise "medium" if any is, otherwise "high".
LOW_CONFIDENCE_FACTOR_THRESHOLD = 2

# Weighted raw score -> integer 1-5 rounding rule.
# "half_up": 2.5 -> 3, 2.49 -> 2 (round half away from zero, not banker's).
SCORE_ROUNDING = "half_up"
SCORE_MIN = 1
SCORE_MAX = 5

# ---------------------------------------------------------------------------
# Risk score and bands
# ---------------------------------------------------------------------------

# Likelihood x impact (1-25) bands. (minimum product, band)
RISK_BANDS = ((1, "low"), (5, "medium"), (10, "high"), (17, "critical"))

# A finding qualifies as a top-risk candidate when likelihood x impact is at
# least this value (i.e. Medium band or higher).
MIN_QUALIFYING_LIKELIHOOD_IMPACT = 5

# Decimal places for the reported risk score.
RISK_SCORE_DECIMALS = 2

DEFAULT_TOP_RISKS = 5
MIN_TOP_RISKS = 5
MAX_TOP_RISKS = 7

# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

ORGANIZATION_TIMEZONE = "Africa/Nairobi"
WORKING_HOURS_START = 8  # inclusive, local hour
WORKING_HOURS_END = 18  # exclusive, local hour
WORKING_DAYS = (0, 1, 2, 3, 4)  # Monday=0 ... Friday=4

# New-country login
NEW_COUNTRY_BASELINE_DAYS = HISTORICAL_WINDOW_DAYS
# Users with fewer prior successful logins than this are not evaluated
# (insufficient baseline -> no claim either way).
NEW_COUNTRY_MIN_BASELINE_EVENTS = 5

# Impossible travel
IMPOSSIBLE_TRAVEL_MAX_INTERVAL_HOURS = 12
IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM = 500
IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH = 900  # roughly commercial airliner speed
EARTH_RADIUS_KM = 6371.0

# Off-hours administrative activity
OFF_HOURS_USER_TYPES = ("admin",)  # service accounts are expected to run off-hours

# Excessive failed logins
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 15

# Unusual data access
UNUSUAL_ACCESS_BASELINE_DAYS = HISTORICAL_WINDOW_DAYS
UNUSUAL_ACCESS_MIN_BASELINE_EVENTS = 5
UNUSUAL_ACCESS_MULTIPLIER = 5.0  # volume above N x the user's mean for the asset
UNUSUAL_ACCESS_MIN_RECORDS = 5_000  # ignore spikes smaller than this

ANOMALY_TYPES = (
    "new_country",
    "impossible_travel",
    "off_hours_admin",
    "excessive_failed_logins",
    "unusual_data_access",
)

# Labels and descriptions copied into the report's `anomaly_types` block.
ANOMALY_TYPE_INFO = {
    "new_country": {
        "label": "Login from new country",
        "description": f"First login from this country for the user in the last {NEW_COUNTRY_BASELINE_DAYS} days",
    },
    "impossible_travel": {
        "label": "Impossible travel",
        "description": "Two logins too far apart to travel between in the time given "
        f"(over {IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH} km/h)",
    },
    "off_hours_admin": {
        "label": "Off-hours admin login",
        "description": f"Admin or root login outside {WORKING_HOURS_START:02d}:00-{WORKING_HOURS_END:02d}:00 local time",
    },
    "excessive_failed_logins": {
        "label": "Excessive failed logins",
        "description": f"{FAILED_LOGIN_THRESHOLD} or more failed logins from one IP against one asset "
        f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes",
    },
    "unusual_data_access": {
        "label": "Unusual data access",
        "description": f"Records read more than {UNUSUAL_ACCESS_MULTIPLIER:g}x the user's "
        f"{UNUSUAL_ACCESS_BASELINE_DAYS}-day average for the asset",
    },
}

# Confidence assigned to each detector's output (configurable per type).
ANOMALY_CONFIDENCE = {
    "new_country": "medium",
    "impossible_travel": "high",
    "off_hours_admin": "medium",
    "excessive_failed_logins": "high",
    "unusual_data_access": "high",
}


def report_timestamp() -> datetime:
    """Timestamp used for generated reports."""
    if USE_REFERENCE_TIME_FOR_REPORTS:
        return REFERENCE_TIME
    return datetime.now(timezone.utc)


def likelihood_rule_text() -> str:
    base = ", ".join(f"{level} = {score}" for level, score in LIKELIHOOD_BY_EXPOSURE.items())
    return f"{base}; +{LIKELIHOOD_ANOMALOUS_BONUS} if anomalous access; max {LIKELIHOOD_MAX}"


def _validate() -> None:
    total = round(sum(IMPACT_WEIGHTS.values()), 9)
    if total != 1.0:
        raise ValueError(f"IMPACT_WEIGHTS must sum to 1.0 (100%), got {total}")
    for name, table, keys in (
        ("SEVERITY_WEIGHTS", SEVERITY_WEIGHTS, ALLOWED_SEVERITIES),
        ("EXPOSURE_WEIGHTS", EXPOSURE_WEIGHTS, ALLOWED_EXPOSURES),
        ("SENSITIVITY_WEIGHTS", SENSITIVITY_WEIGHTS, ALLOWED_SENSITIVITIES),
        ("LIKELIHOOD_BY_EXPOSURE", LIKELIHOOD_BY_EXPOSURE, ALLOWED_EXPOSURES),
        ("REMEDIATION_WINDOW_BY_SEVERITY", REMEDIATION_WINDOW_BY_SEVERITY, ALLOWED_SEVERITIES),
        ("ANOMALY_TYPE_INFO", ANOMALY_TYPE_INFO, ANOMALY_TYPES),
    ):
        if set(table) != set(keys):
            raise ValueError(f"{name} must define exactly {keys}")
    if set(REMEDIATION_WINDOW_BY_SEVERITY.values()) - set(REMEDIATION_WINDOWS):
        raise ValueError("REMEDIATION_WINDOW_BY_SEVERITY uses an unknown window")
    if not MIN_TOP_RISKS <= DEFAULT_TOP_RISKS <= MAX_TOP_RISKS:
        raise ValueError("DEFAULT_TOP_RISKS must lie between MIN_TOP_RISKS and MAX_TOP_RISKS")
    if not 0 <= WORKING_HOURS_START < WORKING_HOURS_END <= 24:
        raise ValueError("Invalid working hours")


_validate()
