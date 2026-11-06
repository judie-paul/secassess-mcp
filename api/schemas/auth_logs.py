"""Authentication / access log schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import Field

from api.schemas.common import AuthOutcome, Page, StrictModel


class AuthEvent(StrictModel):
    event_id: str
    organization_id: str
    timestamp: datetime
    username: str
    user_type: Literal["human", "admin", "service"]
    privileged: bool
    source_ip: str
    country: str
    country_code: str = Field(pattern=r"^[A-Z]{2}$", description="ISO 3166-1 alpha-2")
    city: str
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    outcome: AuthOutcome
    auth_method: str
    action: str
    asset_id: str
    user_agent: Optional[str] = None
    records_accessed: Optional[int] = Field(default=None, ge=0)
    failure_reason: Optional[str] = None


AuthEventPage = Page[AuthEvent]
