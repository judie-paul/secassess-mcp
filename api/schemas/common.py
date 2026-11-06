"""Shared schema types."""

from __future__ import annotations

from typing import Generic, List, Literal, TypeVar

from pydantic import BaseModel, ConfigDict

import config

T = TypeVar("T")

Severity = Literal[config.ALLOWED_SEVERITIES]
Exposure = Literal[config.ALLOWED_EXPOSURES]
Sensitivity = Literal[config.ALLOWED_SENSITIVITIES]
Criticality = Literal[config.ALLOWED_CRITICALITIES]
Environment = Literal[config.ALLOWED_ENVIRONMENTS]
FindingStatus = Literal[config.ALLOWED_FINDING_STATUSES]
AuthOutcome = Literal[config.ALLOWED_AUTH_OUTCOMES]
Exploitability = Literal[config.ALLOWED_EXPLOITABILITY]
Service = Literal[config.ALLOWED_SERVICES]
AnomalyType = Literal[config.ANOMALY_TYPES]
RemediationWindow = Literal[config.REMEDIATION_WINDOWS]
Confidence = Literal["high", "medium", "low"]


class StrictModel(BaseModel):
    """Base model that rejects unknown fields, so data-file typos surface early."""

    model_config = ConfigDict(extra="forbid")


class Page(BaseModel, Generic[T]):
    """A page of results plus the information needed to fetch the next one."""

    total: int
    limit: int
    offset: int
    items: List[T]


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
