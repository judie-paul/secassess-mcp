"""Impact model: how bad would it be if this risk materialised?

Factors (weights in config.IMPACT_WEIGHTS):

* data_sensitivity     - asset sensitivity, raised if the inventory shows PII
                         or financial data.
* business_criticality - asset business criticality.
* affected_records     - inventory record count bands. Unknown counts are NOT
                         treated as zero: they get a neutral score with low
                         confidence.
* financial_impact     - financial data -> direct loss possible; PII ->
                         regulatory fines; otherwise from sensitivity.
* operational_impact   - environment, adjusted by criticality in production.
"""

from __future__ import annotations

from typing import Optional

import config
from analysis.scoring import combine, make_factor, score_from_thresholds
from api.schemas.assets import Asset
from api.schemas.inventory import DataInventoryRecord
from api.schemas.risks import ComponentScore

W = config.IMPACT_WEIGHTS
C = config.IMPACT_CRITERIA


def _factor(name: str, score: int, basis: str, confidence: str):
    return make_factor(name, score, W, C, basis, confidence)


def effective_sensitivity(asset: Asset, inventory: Optional[DataInventoryRecord]) -> str:
    """Asset sensitivity, raised to pii/financial if the inventory says so."""
    candidates = [asset.data_sensitivity]
    if inventory is not None:
        if inventory.contains_pii:
            candidates.append("pii")
        if inventory.contains_financial_data:
            candidates.append("financial")
    # Highest score wins; ties broken by the configured vocabulary order.
    return max(
        candidates,
        key=lambda s: (config.SENSITIVITY_SCORES[s], -config.ALLOWED_SENSITIVITIES.index(s)),
    )


def data_sensitivity_factor(asset: Asset, inventory: Optional[DataInventoryRecord]):
    level = effective_sensitivity(asset, inventory)
    source = "asset classification" if level == asset.data_sensitivity else "data inventory"
    return _factor(
        "data_sensitivity",
        config.SENSITIVITY_SCORES[level],
        f"Data sensitivity '{level}' (from {source})",
        config.CONFIDENCE_HIGH,
    )


def business_criticality_factor(asset: Asset):
    return _factor(
        "business_criticality",
        config.CRITICALITY_SCORES[asset.business_criticality],
        f"Business criticality '{asset.business_criticality}'",
        config.CONFIDENCE_HIGH,
    )


def affected_records_factor(inventory: Optional[DataInventoryRecord]):
    if inventory is None:
        return _factor(
            "affected_records",
            config.NEUTRAL_FACTOR_SCORES["affected_records"],
            "Asset has no data inventory entry; record count unknown, neutral score applied",
            config.CONFIDENCE_LOW,
        )
    if inventory.record_count is None:
        note = f" ({inventory.record_count_note})" if inventory.record_count_note else ""
        return _factor(
            "affected_records",
            config.NEUTRAL_FACTOR_SCORES["affected_records"],
            f"Record count unknown{note}; neutral score applied, not treated as zero",
            config.CONFIDENCE_LOW,
        )
    return _factor(
        "affected_records",
        score_from_thresholds(inventory.record_count, config.RECORD_COUNT_THRESHOLDS),
        f"{inventory.record_count:,} records in data inventory",
        config.CONFIDENCE_HIGH,
    )


def financial_impact_factor(asset: Asset, inventory: Optional[DataInventoryRecord]):
    scores = config.FINANCIAL_IMPACT_SCORES
    if inventory is not None:
        if inventory.contains_financial_data:
            return _factor("financial_impact", scores["financial_data"], "Holds financial data", config.CONFIDENCE_HIGH)
        if inventory.contains_pii:
            return _factor(
                "financial_impact", scores["pii"], "Holds PII (regulatory fines / notification costs)", config.CONFIDENCE_HIGH
            )
        key = asset.data_sensitivity if asset.data_sensitivity in scores else None
        if key:
            return _factor(
                "financial_impact", scores[key], f"Derived from '{key}' classification", config.CONFIDENCE_MEDIUM
            )
    sensitivity = asset.data_sensitivity
    key = "financial_data" if sensitivity == "financial" else sensitivity
    if key in scores:
        return _factor(
            "financial_impact",
            scores[key],
            f"No inventory entry; derived from asset classification '{sensitivity}'",
            config.CONFIDENCE_MEDIUM,
        )
    return _factor(  # pragma: no cover - every sensitivity is mapped by default
        "financial_impact",
        config.NEUTRAL_FACTOR_SCORES["financial_impact"],
        "Financial consequence unknown; neutral score applied",
        config.CONFIDENCE_LOW,
    )


def operational_impact_factor(asset: Asset):
    score = config.OPERATIONAL_IMPACT_BY_ENVIRONMENT[asset.environment]
    basis = f"Environment '{asset.environment}'"
    if asset.environment == "production":
        adjustment = config.OPERATIONAL_CRITICALITY_ADJUSTMENT[asset.business_criticality]
        score += adjustment
        basis += f", criticality '{asset.business_criticality}' adjustment {adjustment:+d}"
    score = max(config.SCORE_MIN, min(config.SCORE_MAX, score))
    return _factor("operational_impact", score, basis, config.CONFIDENCE_HIGH)


def compute_impact(asset: Asset, inventory: Optional[DataInventoryRecord]) -> ComponentScore:
    factors = [
        data_sensitivity_factor(asset, inventory),
        business_criticality_factor(asset),
        affected_records_factor(inventory),
        financial_impact_factor(asset, inventory),
        operational_impact_factor(asset),
    ]
    return combine(factors, W)
