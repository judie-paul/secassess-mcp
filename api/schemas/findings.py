"""Security finding schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from api.schemas.common import Exploitability, Exposure, FindingStatus, Page, Service, Severity, StrictModel


class Finding(StrictModel):
    finding_id: str
    organization_id: str
    asset_id: str
    service: Service
    title: str
    description: str
    category: str
    severity: Severity
    exposure: Exposure
    exploitability: Optional[Exploitability] = None
    exploitation_confirmed: bool = False
    detection_source: str
    detected_at: datetime
    status: FindingStatus


FindingPage = Page[Finding]
