"""Data inventory schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from api.schemas.common import Criticality, Exposure, Sensitivity, StrictModel


class DataInventoryRecord(StrictModel):
    """Raw inventory entry as stored in data_inventory.json."""

    asset_id: str
    organization_id: str
    data_classification: str
    data_categories: List[str]
    contains_pii: bool
    contains_financial_data: bool
    record_count: Optional[int] = Field(default=None, ge=0)
    record_count_note: Optional[str] = None
    storage_location: str


class DataInventoryEntry(BaseModel):
    """Inventory entry joined with its asset."""

    asset_id: str
    asset_name: str
    data_classification: str
    data_categories: List[str]
    data_sensitivity: Sensitivity
    record_count: Optional[int]
    record_count_note: Optional[str]
    contains_pii: bool
    contains_financial_data: bool
    storage_location: str
    exposure: Exposure
    business_criticality: Criticality
