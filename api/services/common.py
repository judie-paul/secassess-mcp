"""Helpers shared by the service modules."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence, Tuple, TypeVar

import config
from api.data_access.json_repository import JsonRepository
from api.errors import InvalidRequestError, NotFoundError
from api.schemas.common import Page
from api.schemas.organizations import Organization

T = TypeVar("T")


def require_organization(repo: JsonRepository, organization_id: str) -> Organization:
    organization = repo.organization(organization_id)
    if organization is None:
        raise NotFoundError("Organization", organization_id)
    return organization


def paginate(items: Sequence[T], limit: int, offset: int) -> Page[T]:
    return Page[T](total=len(items), limit=limit, offset=offset, items=list(items[offset : offset + limit]))


def as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Treat naive datetimes as UTC and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_window(
    start: Optional[datetime],
    end: Optional[datetime],
    default_start: Optional[datetime] = None,
    default_end: Optional[datetime] = None,
) -> Tuple[Optional[datetime], Optional[datetime]]:
    start = as_utc(start) or default_start
    end = as_utc(end) or default_end
    if start and end and start > end:
        raise InvalidRequestError("start_time must be earlier than or equal to end_time")
    return start, end


def default_analysis_window() -> Tuple[datetime, datetime]:
    return config.DEFAULT_ASSESSMENT_START, config.DEFAULT_ASSESSMENT_END
