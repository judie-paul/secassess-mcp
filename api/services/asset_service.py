"""Asset detail retrieval."""

from __future__ import annotations

import config
from analysis.controls import failed_controls
from api.data_access.json_repository import JsonRepository
from api.errors import NotFoundError
from api.schemas.assets import AssetDetail, AssetSecurityInfo
from api.services.anomaly_service import AnomalyService
from api.services.common import require_organization
from api.services.finding_service import FindingService, is_active
from api.services.inventory_service import InventoryService


class AssetService:
    def __init__(
        self,
        repo: JsonRepository,
        findings: FindingService,
        inventory: InventoryService,
        anomalies: AnomalyService,
    ):
        self.repo = repo
        self.findings = findings
        self.inventory = inventory
        self.anomalies = anomalies

    def get_asset(self, organization_id: str, asset_id: str) -> AssetDetail:
        require_organization(self.repo, organization_id)
        asset = next((a for a in self.repo.assets_for(organization_id) if a.asset_id == asset_id), None)
        if asset is None:
            raise NotFoundError("Asset", asset_id)

        related = self.findings.findings_for_asset(organization_id, asset_id)
        active = [f for f in related if is_active(f)]
        anomalies = [a for a in self.anomalies.default_window_anomalies(organization_id) if a.asset_id == asset_id]
        record = self.inventory.record_for(organization_id, asset_id)
        controls = asset.security_controls.model_dump()
        events = sum(
            1
            for e in self.repo.auth_logs_for(organization_id)
            if e.asset_id == asset_id and config.DEFAULT_ASSESSMENT_START <= e.timestamp <= config.DEFAULT_ASSESSMENT_END
        )

        return AssetDetail(
            **asset.model_dump(),
            record_count=record.record_count if record else None,
            related_findings=related,
            related_anomalies=anomalies,
            security_info=AssetSecurityInfo(
                open_findings=len(active),
                highest_open_severity=active[0].severity if active else None,
                failed_controls=failed_controls(asset, active),
                unknown_controls=sorted(k for k, v in controls.items() if v is None),
                anomaly_ids=[a.anomaly_id for a in anomalies],
                auth_events_observed=events,
            ),
        )
