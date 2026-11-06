"""Assessment report schemas. `AssessmentReport` matches contracts/report_data.example.json exactly."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

import config
from api.schemas.anomalies import ReportAnomaly
from api.schemas.common import RemediationWindow
from api.schemas.risks import ReportRisk


class RiskAnnotation(BaseModel):
    """AI-authored interpretation of one top risk. Numbers and the remediation window
    come from the backend and are never accepted here."""

    model_config = ConfigDict(extra="forbid")

    risk_id: str
    business_impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)

    @field_validator("business_impact", "remediation")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top_risks_limit: int = Field(
        default=config.DEFAULT_TOP_RISKS, ge=config.MIN_TOP_RISKS, le=config.MAX_TOP_RISKS
    )
    annotations: List[RiskAnnotation] = []


class ScoringModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    formula: str
    factors: Dict[str, Dict[str, Union[int, float]]]
    likelihood_rule: str
    remediation_windows: Dict[str, RemediationWindow]


class AnomalyTypeInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    description: str


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_assets: int
    total_findings: int
    by_severity: Dict[str, int]
    sensitive_assets: int
    sensitive_assets_exposed: int
    anomalies_detected: int


class RiskMatrixCell(BaseModel):
    model_config = ConfigDict(extra="forbid")

    likelihood: int
    impact: int
    count: int


class AssessmentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    generated_at: datetime
    organisation: str
    scoring_model: ScoringModel
    anomaly_types: Dict[str, AnomalyTypeInfo]
    summary: ReportSummary
    findings_by_service: Dict[str, int]
    risk_matrix: List[RiskMatrixCell]
    top_risks: List[ReportRisk]
    anomalies: List[ReportAnomaly]
