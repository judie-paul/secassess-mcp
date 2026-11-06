"""Anomaly detection over authentication logs."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

import config
from analysis.detectors import run_detectors
from api.data_access.json_repository import JsonRepository
from api.errors import NotFoundError
from api.schemas.anomalies import Anomaly, AnomalyEvidence, AnomalyList
from api.services.common import require_organization, resolve_window

ANOMALY_NOTE = (
    "Anomalies are detected from authentication logs and indicate behaviour that warrants "
    "investigation. They are not confirmed malicious activity."
)


class AnomalyService:
    def __init__(self, repo: JsonRepository):
        self.repo = repo
        self._cache: Dict[Tuple[str, datetime, datetime], List[Anomaly]] = {}

    def detect_all(self, organization_id: str, start: datetime, end: datetime) -> List[Anomaly]:
        key = (organization_id, start, end)
        if key not in self._cache:
            events = self.repo.auth_logs_for(organization_id)
            self._cache[key] = run_detectors(events, start, end)
        return self._cache[key]

    def detect(
        self,
        organization_id: str,
        anomaly_type: Optional[str] = None,
        asset_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> AnomalyList:
        require_organization(self.repo, organization_id)
        if asset_id is not None and not any(a.asset_id == asset_id for a in self.repo.assets_for(organization_id)):
            raise NotFoundError("Asset", asset_id)
        start, end = resolve_window(
            start_time, end_time, config.DEFAULT_ASSESSMENT_START, config.DEFAULT_ASSESSMENT_END
        )
        found = [
            a
            for a in self.detect_all(organization_id, start, end)
            if (anomaly_type is None or a.type == anomaly_type) and (asset_id is None or a.asset_id == asset_id)
        ]
        return AnomalyList(
            organization_id=organization_id,
            total=len(found),
            analysis_start=start,
            analysis_end=end,
            note=ANOMALY_NOTE,
            items=[a.to_report() for a in found],
            evidence={
                a.anomaly_id: AnomalyEvidence(
                    confidence=a.confidence, supporting_event_ids=a.supporting_event_ids, context=a.context
                )
                for a in found
            },
        )

    def default_window_anomalies(self, organization_id: str) -> List[Anomaly]:
        return self.detect_all(organization_id, config.DEFAULT_ASSESSMENT_START, config.DEFAULT_ASSESSMENT_END)
