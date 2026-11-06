"""Authentication / access log queries."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import config
from api.data_access.json_repository import JsonRepository
from api.schemas.auth_logs import AuthEvent
from api.schemas.common import Page
from api.services.common import paginate, require_organization, resolve_window


class AuthLogService:
    def __init__(self, repo: JsonRepository):
        self.repo = repo

    def query(
        self,
        organization_id: str,
        username: Optional[str] = None,
        asset_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        country: Optional[str] = None,
        outcome: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = config.DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> Page[AuthEvent]:
        """All filters combine with AND. Results are newest first."""
        require_organization(self.repo, organization_id)
        start, end = resolve_window(start_time, end_time)
        events = [
            e
            for e in self.repo.auth_logs_for(organization_id)
            if (username is None or e.username.lower() == username.lower())
            and (asset_id is None or e.asset_id == asset_id)
            and (source_ip is None or e.source_ip == source_ip)
            and (country is None or country.lower() in (e.country.lower(), e.country_code.lower()))
            and (outcome is None or e.outcome == outcome)
            and (start is None or e.timestamp >= start)
            and (end is None or e.timestamp <= end)
        ]
        events.sort(key=lambda e: (e.timestamp, e.event_id), reverse=True)
        return paginate(events, limit, offset)
