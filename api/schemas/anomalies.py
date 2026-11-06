"""Anomaly schemas.

`ReportAnomaly` is the exact shape used in report_data.example.json.
`Anomaly` extends it with the supporting evidence the detectors produce.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict

from api.schemas.common import AnomalyType, Confidence


class ReportAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anomaly_id: str
    type: AnomalyType
    user: str
    asset_id: Optional[str]
    country: Optional[str]
    timestamp: datetime
    detail: str


class Anomaly(ReportAnomaly):
    organization_id: str
    confidence: Confidence
    supporting_event_ids: List[str]
    context: Dict[str, Any] = {}

    def to_report(self) -> ReportAnomaly:
        return ReportAnomaly(**{name: getattr(self, name) for name in ReportAnomaly.model_fields})


class AnomalyEvidence(BaseModel):
    confidence: Confidence
    supporting_event_ids: List[str]
    context: Dict[str, Any]


class AnomalyList(BaseModel):
    """`items` use the report format; `evidence` (keyed by anomaly_id) holds the supporting detail."""

    organization_id: str
    total: int
    analysis_start: datetime
    analysis_end: datetime
    note: str
    items: List[ReportAnomaly]
    evidence: Dict[str, AnomalyEvidence]
