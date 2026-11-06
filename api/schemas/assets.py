"""Asset schemas."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from api.schemas.anomalies import Anomaly
from api.schemas.common import Criticality, Environment, Exposure, Sensitivity, Service, Severity, StrictModel
from api.schemas.findings import Finding


class SecurityControls(StrictModel):
    """Control states: True = in place, False = missing, None = unknown / not applicable."""

    encryption_at_rest: Optional[bool] = None
    encryption_in_transit: Optional[bool] = None
    mfa_enforced: Optional[bool] = None
    logging_enabled: Optional[bool] = None
    least_privilege: Optional[bool] = None
    network_restricted: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    key_rotation: Optional[bool] = None


class Asset(StrictModel):
    asset_id: str
    organization_id: str
    name: str
    asset_type: str
    service: Service
    region: str
    environment: Environment
    exposure: Exposure
    data_sensitivity: Sensitivity
    business_criticality: Criticality
    owner: str
    description: str
    discovered_at: datetime
    security_controls: SecurityControls
    tags: List[str] = []


class AssetSecurityInfo(BaseModel):
    open_findings: int
    highest_open_severity: Optional[Severity]
    failed_controls: List[str]
    unknown_controls: List[str]
    anomaly_ids: List[str]
    auth_events_observed: int


class AssetDetail(Asset):
    record_count: Optional[int]
    related_findings: List[Finding]
    related_anomalies: List[Anomaly]
    security_info: AssetSecurityInfo
