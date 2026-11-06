"""Organization schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from pydantic import BaseModel

from api.schemas.common import StrictModel
from api.schemas.reports import AnomalyTypeInfo, ReportSummary, RiskMatrixCell, ScoringModel


class Organization(StrictModel):
    organization_id: str
    name: str
    industry: str
    headquarters: str
    employee_count: int
    cloud_provider: str
    aws_account_ids: List[str]
    primary_region: str
    timezone: str


class SecurityStatistics(BaseModel):
    open_findings: int
    assets_by_service: Dict[str, int]
    assets_by_exposure: Dict[str, int]
    findings_by_status: Dict[str, int]
    anomalies_by_type: Dict[str, int]
    assets_with_open_findings: int
    qualifying_risks: int


class OrganizationSummary(BaseModel):
    """Posture overview. The report-level fields use the exact contracts/report_data.example.json format,
    so they can be copied into the final report unchanged."""

    organization_id: str
    schema_version: str
    generated_at: datetime
    organisation: str
    scoring_model: ScoringModel
    anomaly_types: Dict[str, AnomalyTypeInfo]
    summary: ReportSummary
    findings_by_service: Dict[str, int]
    risk_matrix: List[RiskMatrixCell]
    statistics: SecurityStatistics
