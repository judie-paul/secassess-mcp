"""Data inventory retrieval, joined with asset attributes."""

from __future__ import annotations

from typing import List, Optional

from api.data_access.json_repository import JsonRepository
from api.errors import NotFoundError
from api.schemas.inventory import DataInventoryEntry, DataInventoryRecord
from api.services.common import require_organization


class InventoryService:
    def __init__(self, repo: JsonRepository):
        self.repo = repo

    def record_for(self, organization_id: str, asset_id: str) -> Optional[DataInventoryRecord]:
        return next((r for r in self.repo.inventory_for(organization_id) if r.asset_id == asset_id), None)

    def list_inventory(
        self,
        organization_id: str,
        asset_id: Optional[str] = None,
        sensitivity: Optional[str] = None,
        contains_pii: Optional[bool] = None,
        contains_financial_data: Optional[bool] = None,
    ) -> List[DataInventoryEntry]:
        require_organization(self.repo, organization_id)
        assets = {a.asset_id: a for a in self.repo.assets_for(organization_id)}
        if asset_id is not None and asset_id not in assets:
            raise NotFoundError("Asset", asset_id)

        entries = []
        for record in self.repo.inventory_for(organization_id):
            asset = assets[record.asset_id]
            entry = DataInventoryEntry(
                asset_id=record.asset_id,
                asset_name=asset.name,
                data_classification=record.data_classification,
                data_categories=record.data_categories,
                data_sensitivity=asset.data_sensitivity,
                record_count=record.record_count,
                record_count_note=record.record_count_note,
                contains_pii=record.contains_pii,
                contains_financial_data=record.contains_financial_data,
                storage_location=record.storage_location,
                exposure=asset.exposure,
                business_criticality=asset.business_criticality,
            )
            if asset_id is not None and entry.asset_id != asset_id:
                continue
            if sensitivity is not None and entry.data_sensitivity != sensitivity:
                continue
            if contains_pii is not None and entry.contains_pii != contains_pii:
                continue
            if contains_financial_data is not None and entry.contains_financial_data != contains_financial_data:
                continue
            entries.append(entry)
        return sorted(entries, key=lambda e: e.asset_id)
