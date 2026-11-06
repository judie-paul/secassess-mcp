"""Shared, deterministic scoring helpers.

Every function here is pure: the same inputs and configuration always give the
same outputs. Nothing reads the clock.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Dict, List, Sequence, Tuple

import config
from api.schemas.reports import AnomalyTypeInfo, ScoringModel
from api.schemas.risks import ComponentScore, FactorScore, ScoreBreakdown

ROUNDING_RULE_TEXT = (
    "Weighted raw score rounded half-up to the nearest integer "
    "(x.5 rounds up, e.g. 2.5 -> 3, 2.49 -> 2), then clamped to the 1-5 scale."
)


def round_score(raw: float) -> int:
    """Convert a weighted 1-5 raw score to an integer using the configured rule."""
    if config.SCORE_ROUNDING != "half_up":  # pragma: no cover - guarded by config
        raise ValueError(f"Unsupported rounding rule: {config.SCORE_ROUNDING}")
    # Round the float to 6 dp first so binary noise (2.4999999) cannot flip the result.
    value = Decimal(str(round(raw, 6))).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return max(config.SCORE_MIN, min(config.SCORE_MAX, int(value)))


def score_from_thresholds(value: float, thresholds: Sequence[Tuple[float, int]]) -> int:
    """Return the score of the highest threshold whose minimum ``value`` meets."""
    result = thresholds[0][1]
    for minimum, score in thresholds:
        if value >= minimum:
            result = score
    return result


def make_factor(
    name: str,
    score: int,
    weights: Dict[str, float],
    criteria: Dict[str, Dict[int, str]],
    basis: str,
    confidence: str,
) -> FactorScore:
    if not config.SCORE_MIN <= score <= config.SCORE_MAX:
        raise ValueError(f"Factor {name} score {score} outside 1-5")
    weight = weights[name]
    return FactorScore(
        factor=name,
        score=score,
        weight=weight,
        weighted_score=round(score * weight, 4),
        criterion=criteria[name][score],
        basis=basis,
        confidence=confidence,
    )


def overall_confidence(confidences: Sequence[str]) -> str:
    low = sum(1 for c in confidences if c == config.CONFIDENCE_LOW)
    if low >= config.LOW_CONFIDENCE_FACTOR_THRESHOLD:
        return config.CONFIDENCE_LOW
    if low or any(c == config.CONFIDENCE_MEDIUM for c in confidences):
        return config.CONFIDENCE_MEDIUM
    return config.CONFIDENCE_HIGH


def combine(factors: List[FactorScore], weights: Dict[str, float]) -> ComponentScore:
    """Weighted sum of factors -> integer 1-5 component score."""
    names = [f.factor for f in factors]
    if sorted(names) != sorted(weights):
        raise ValueError(f"Expected factors {sorted(weights)}, got {sorted(names)}")
    raw = round(sum(f.score * f.weight for f in factors), 4)
    return ComponentScore(
        factors=factors,
        raw_score=raw,
        score=round_score(raw),
        rounding_rule=ROUNDING_RULE_TEXT,
        confidence=overall_confidence([f.confidence for f in factors]),
    )


def risk_score(likelihood: int, impact: int) -> int:
    """Risk score = likelihood x impact (1-25)."""
    for value in (likelihood, impact):
        if not config.SCORE_MIN <= value <= config.SCORE_MAX:
            raise ValueError(f"Likelihood/impact must be 1-5, got {value}")
    return likelihood * impact


def risk_band(score: int) -> str:
    band = config.RISK_BANDS[0][1]
    for minimum, name in config.RISK_BANDS:
        if score >= minimum:
            band = name
    return band


def score_breakdown(severity: str, exposure: str, sensitivity: str, anomalous_access: bool) -> ScoreBreakdown:
    activity = "anomalous" if anomalous_access else "normal"
    return ScoreBreakdown(
        severity=config.SEVERITY_WEIGHTS[severity],
        exposure=config.EXPOSURE_WEIGHTS[exposure],
        data_sensitivity=config.SENSITIVITY_WEIGHTS[sensitivity],
        activity=config.ACTIVITY_WEIGHTS[activity],
    )


def weighted_risk_score(breakdown: ScoreBreakdown) -> float:
    """Reported risk score: the product of the four breakdown weights."""
    value = breakdown.severity * breakdown.exposure * breakdown.data_sensitivity * breakdown.activity
    return round(value, config.RISK_SCORE_DECIMALS)


def scoring_model() -> ScoringModel:
    """The `scoring_model` block of the report, built from config so it always matches the scores."""
    return ScoringModel(
        version=config.SCORING_MODEL_VERSION,
        formula=config.SCORING_FORMULA,
        factors={
            "severity": dict(config.SEVERITY_WEIGHTS),
            "exposure": dict(config.EXPOSURE_WEIGHTS),
            "data_sensitivity": {
                config.REPORT_SENSITIVITY_LABELS[k]: v for k, v in config.SENSITIVITY_WEIGHTS.items()
            },
            "activity": dict(config.ACTIVITY_WEIGHTS),
        },
        likelihood_rule=config.likelihood_rule_text(),
        remediation_windows=dict(config.REMEDIATION_WINDOW_BY_SEVERITY),
    )


def anomaly_types() -> Dict[str, AnomalyTypeInfo]:
    return {name: AnomalyTypeInfo(**config.ANOMALY_TYPE_INFO[name]) for name in config.ANOMALY_TYPES}


RISK_SCORE_FORMULA = (
    f"score = {config.SCORING_FORMULA}; likelihood = {config.likelihood_rule_text()}; "
    "impact is a 1-5 weighted factor model; likelihood x impact breaks score ties"
)
