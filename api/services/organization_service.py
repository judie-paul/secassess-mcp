"""Organization-level security posture summary."""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable

import config
from analysis import scoring
from api.data_access.json_repository import JsonRepository
from api.schemas.organizations import OrganizationSummary, SecurityStatistics
from api.schemas.reports import ReportSummary
from api.services.anomaly_service import AnomalyService
from api.services.common import require_organization
from api.services.finding_service import is_active
from api.services.risk_service import RiskService


def ordered_counts(values: Iterable[str], order: Iterable[str]) -> Dict[str, int]:
    """Counts for every key in ``order`` (including zeros), in that order."""
    counts = Counter(values)
    return {key: counts.get(key, 0) for key in order}


def counts_by_frequency(values: Iterable[str]) -> Dict[str, int]:
    """Counts ordered by count (descending), then key, as in the example report."""
    counts = Counter(values)
    return {key: counts[key] for key in sorted(counts, key=lambda k: (-counts[k], k))}


class OrganizationService:
    def __init__(self, repo: JsonRepository, anomalies: AnomalyService, risks: RiskService):
        self.repo = repo
        self.anomalies = anomalies
        self.risks = risks

    def report_summary(self, organization_id: str) -> ReportSummary:
        require_organization(self.repo, organization_id)
        assets = self.repo.assets_for(organization_id)
        findings = self.repo.findings_for(organization_id)
        sensitive = [a for a in assets if a.data_sensitivity in config.SENSITIVE_DATA_LEVELS]
        return ReportSummary(
            total_assets=len(assets),
            total_findings=len(findings),
            by_severity=ordered_counts((f.severity for f in findings), config.ALLOWED_SEVERITIES),
            sensitive_assets=len(sensitive),
            sensitive_assets_exposed=sum(1 for a in sensitive if a.exposure in config.EXPOSED_LEVELS),
            anomalies_detected=len(self.anomalies.default_window_anomalies(organization_id)),
        )

    def findings_by_service(self, organization_id: str) -> Dict[str, int]:
        return counts_by_frequency(f.service for f in self.repo.findings_for(organization_id))

    def summary(self, organization_id: str) -> OrganizationSummary:
        organization = require_organization(self.repo, organization_id)
        assets = self.repo.assets_for(organization_id)
        findings = self.repo.findings_for(organization_id)
        anomalies = self.anomalies.default_window_anomalies(organization_id)
        services_present = sorted({a.service for a in assets})

        return OrganizationSummary(
            organization_id=organization.organization_id,
            schema_version=config.SCHEMA_VERSION,
            generated_at=config.report_timestamp(),
            organisation=organization.name,
            scoring_model=scoring.scoring_model(),
            anomaly_types=scoring.anomaly_types(),
            summary=self.report_summary(organization_id),
            findings_by_service=self.findings_by_service(organization_id),
            risk_matrix=self.risks.risk_matrix(organization_id),
            statistics=SecurityStatistics(
                open_findings=sum(1 for f in findings if is_active(f)),
                assets_by_service=ordered_counts((a.service for a in assets), services_present),
                assets_by_exposure=ordered_counts((a.exposure for a in assets), config.ALLOWED_EXPOSURES),
                findings_by_status=ordered_counts((f.status for f in findings), config.ALLOWED_FINDING_STATUSES),
                anomalies_by_type=ordered_counts((a.type for a in anomalies), config.ANOMALY_TYPES),
                assets_with_open_findings=len({f.asset_id for f in findings if is_active(f)}),
                qualifying_risks=len(self.risks.ranked_risks(organization_id)),
            ),
        )
