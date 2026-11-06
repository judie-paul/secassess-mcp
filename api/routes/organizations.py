"""Organization-scoped API routes. Handlers only translate HTTP <-> service calls."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, Query, Response, status

import config
from api.dependencies import Services, get_services
from api.schemas.anomalies import AnomalyList
from api.schemas.assets import AssetDetail
from api.schemas.auth_logs import AuthEventPage
from api.schemas.common import AnomalyType, AuthOutcome, ErrorResponse, FindingStatus, Sensitivity, Service, Severity
from api.schemas.findings import FindingPage
from api.schemas.inventory import DataInventoryEntry
from api.schemas.organizations import OrganizationSummary
from api.schemas.reports import AssessmentReport, AssessmentRequest
from api.schemas.risks import TopRisksResponse

ERRORS = {404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}}

router = APIRouter(prefix="/organizations/{organization_id}", tags=["organizations"], responses=ERRORS)

Limit = Query(config.DEFAULT_PAGE_LIMIT, ge=1, le=config.MAX_PAGE_LIMIT)
Offset = Query(0, ge=0)


@router.get("/summary", response_model=OrganizationSummary)
def get_summary(organization_id: str, services: Services = Depends(get_services)):
    return services.organizations.summary(organization_id)


@router.get("/findings", response_model=FindingPage)
def list_findings(
    organization_id: str,
    severity: Optional[Severity] = None,
    service: Optional[Service] = None,
    status_: Optional[FindingStatus] = Query(None, alias="status"),
    asset_id: Optional[str] = None,
    limit: int = Limit,
    offset: int = Offset,
    services: Services = Depends(get_services),
):
    return services.findings.list_findings(organization_id, severity, service, status_, asset_id, limit, offset)


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(organization_id: str, asset_id: str, services: Services = Depends(get_services)):
    return services.assets.get_asset(organization_id, asset_id)


@router.get("/auth-logs", response_model=AuthEventPage)
def query_auth_logs(
    organization_id: str,
    username: Optional[str] = None,
    asset_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    country: Optional[str] = Query(None, description="Country name or ISO code, e.g. Brazil or BR"),
    outcome: Optional[AuthOutcome] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = Limit,
    offset: int = Offset,
    services: Services = Depends(get_services),
):
    return services.auth_logs.query(
        organization_id, username, asset_id, source_ip, country, outcome, start_time, end_time, limit, offset
    )


@router.get("/risks", response_model=TopRisksResponse)
def top_risks(
    organization_id: str,
    limit: int = Query(config.DEFAULT_TOP_RISKS, ge=config.MIN_TOP_RISKS, le=config.MAX_TOP_RISKS),
    services: Services = Depends(get_services),
):
    return services.risks.top_risks(organization_id, limit)


@router.get("/data-inventory", response_model=List[DataInventoryEntry])
def data_inventory(
    organization_id: str,
    asset_id: Optional[str] = None,
    sensitivity: Optional[Sensitivity] = None,
    contains_pii: Optional[bool] = None,
    contains_financial_data: Optional[bool] = None,
    services: Services = Depends(get_services),
):
    return services.inventory.list_inventory(
        organization_id, asset_id, sensitivity, contains_pii, contains_financial_data
    )


@router.get("/anomalies", response_model=AnomalyList)
def detect_anomalies(
    organization_id: str,
    anomaly_type: Optional[AnomalyType] = None,
    asset_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    services: Services = Depends(get_services),
):
    return services.anomalies.detect(organization_id, anomaly_type, asset_id, start_time, end_time)


@router.post("/assessments", response_model=AssessmentReport, status_code=status.HTTP_201_CREATED)
def create_assessment(
    organization_id: str,
    response: Response,
    request: Optional[AssessmentRequest] = Body(None),
    services: Services = Depends(get_services),
):
    """Body is exactly the report_data.example.json format. Report ID, draft/complete status and any
    insufficient-risk note are returned in the Location, X-Report-Id, X-Report-Status and
    X-Top-Risks-Note headers."""
    result = services.reports.create(organization_id, request or AssessmentRequest())
    response.headers["Location"] = f"/organizations/{organization_id}/assessments/{result.report_id}"
    response.headers["X-Report-Id"] = result.report_id
    response.headers["X-Report-Status"] = result.status
    if result.note:
        response.headers["X-Top-Risks-Note"] = result.note
    return result.report


@router.get("/assessments/{report_id}", response_model=AssessmentReport)
def get_assessment(organization_id: str, report_id: str, services: Services = Depends(get_services)):
    return services.reports.get(organization_id, report_id)
