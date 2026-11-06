"""Security findings retrieval and filtering."""

from __future__ import annotations

from typing import List, Optional

import config
from api.data_access.json_repository import JsonRepository
from api.schemas.common import Page
from api.schemas.findings import Finding
from api.services.common import paginate, require_organization

_SEVERITY_ORDER = {s: i for i, s in enumerate(config.ALLOWED_SEVERITIES)}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then newest, then by ID for a stable order."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER[f.severity], -f.detected_at.timestamp(), f.finding_id),
    )


def is_active(finding: Finding) -> bool:
    return finding.status in config.ACTIVE_FINDING_STATUSES


class FindingService:
    def __init__(self, repo: JsonRepository):
        self.repo = repo

    def list_findings(
        self,
        organization_id: str,
        severity: Optional[str] = None,
        service: Optional[str] = None,
        status: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = config.DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> Page[Finding]:
        require_organization(self.repo, organization_id)
        findings = [
            f
            for f in self.repo.findings_for(organization_id)
            if (severity is None or f.severity == severity)
            and (service is None or f.service.lower() == service.lower())
            and (status is None or f.status == status)
            and (asset_id is None or f.asset_id == asset_id)
        ]
        return paginate(sort_findings(findings), limit, offset)

    def findings_for_asset(self, organization_id: str, asset_id: str, active_only: bool = False) -> List[Finding]:
        findings = [f for f in self.repo.findings_for(organization_id) if f.asset_id == asset_id]
        if active_only:
            findings = [f for f in findings if is_active(f)]
        return sort_findings(findings)
