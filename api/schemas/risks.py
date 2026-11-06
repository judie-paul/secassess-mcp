"""Risk schemas.

`ReportRisk` is the exact top-risk shape from contracts/report_data.example.json.
The likelihood/impact detail is returned separately in `RiskScoringDetail`,
keyed by risk_id, so the report shape stays exact.
"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict

from api.schemas.common import Confidence, Exposure, RemediationWindow, Service, Severity


class FactorScore(BaseModel):
    factor: str
    score: int
    weight: float
    weighted_score: float
    criterion: str
    basis: str
    confidence: Confidence


class ComponentScore(BaseModel):
    """A weighted 1-5 score (impact) with its factors."""

    factors: List[FactorScore]
    raw_score: float
    score: int
    rounding_rule: str
    confidence: Confidence


class LikelihoodDetail(BaseModel):
    """How the likelihood rule was applied to one risk."""

    rule: str
    exposure: Exposure
    base: int
    anomalous_access: bool
    anomalous_bonus: int
    score: int


class ScoreBreakdown(BaseModel):
    """The four multipliers whose product is the risk score."""

    model_config = ConfigDict(extra="forbid")

    severity: int
    exposure: float
    data_sensitivity: float
    activity: float


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["findings", "data_inventory", "auth_logs"]
    ref: str
    detail: str


class ReportRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int
    risk_id: str
    asset_id: str
    service: Service
    title: str
    severity: Severity
    exposure: Exposure
    data_sensitivity: str
    record_count: Optional[int]
    anomalous_access: bool
    score: float
    score_breakdown: ScoreBreakdown
    likelihood: int
    impact: int
    evidence: List[EvidenceRef]
    business_impact: Optional[str] = None
    remediation: Optional[str] = None
    remediation_window: RemediationWindow


class RiskScoringDetail(BaseModel):
    finding_id: str
    score_formula: str
    likelihood: LikelihoodDetail
    impact: ComponentScore
    likelihood_x_impact: int
    likelihood_x_impact_band: Severity
    confidence: Confidence


class ScoredRisk(BaseModel):
    """Internal: one scored active finding, before top-risk selection."""

    finding_id: str
    asset_id: str
    risk: ReportRisk
    detail: RiskScoringDetail


class TopRisksResponse(BaseModel):
    organization_id: str
    requested_limit: int
    returned: int
    qualifying_risks: int
    sufficient_risks: bool
    message: Optional[str]
    items: List[ReportRisk]
    scoring_details: Dict[str, RiskScoringDetail]
