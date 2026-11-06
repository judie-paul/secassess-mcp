"""The seven MCP tools. Each validates its arguments and calls one backend endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, Literal, Optional
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

import config
from mcp_server.client import BackendClient, BackendError

TOOL_NAMES = (
    "get_organization_summary",
    "list_findings",
    "get_asset",
    "query_auth_logs",
    "top_risks",
    "get_data_inventory",
    "detect_anomalies",
)

OrgId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$", description="Organization ID, e.g. org-001")]
AssetId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$", description="Asset ID, e.g. a-rds-001")]
OptAssetId = Annotated[Optional[str], Field(default=None, pattern=r"^[A-Za-z0-9_-]+$", description="Filter by asset ID")]
PageLimit = Annotated[int, Field(ge=1, le=config.MAX_PAGE_LIMIT, description="Maximum records to return")]
Offset = Annotated[int, Field(ge=0, description="Records to skip (pagination)")]
Timestamp = Annotated[Optional[datetime], Field(default=None, description="ISO 8601 UTC timestamp, e.g. 2026-11-01T00:00:00Z")]

Severity = Literal[config.ALLOWED_SEVERITIES]
Service = Literal[config.ALLOWED_SERVICES]
Status = Literal[config.ALLOWED_FINDING_STATUSES]
Outcome = Literal[config.ALLOWED_AUTH_OUTCOMES]
Sensitivity = Literal[config.ALLOWED_SENSITIVITIES]
AnomalyType = Literal[config.ANOMALY_TYPES]


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _org(organization_id: str) -> str:
    return f"/organizations/{quote(organization_id, safe='')}"


def register_tools(server: MCPServer, client: BackendClient) -> None:
    async def call(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return await client.get(path, params)
        except BackendError as exc:
            status = f"HTTP {exc.status_code} " if exc.status_code else ""
            raise ToolError(f"Backend error {status}({exc.code}): {exc.message}") from exc

    @server.tool()
    async def get_organization_summary(organization_id: OrgId) -> Dict[str, Any]:
        """Overall security posture. schema_version, generated_at, organisation, scoring_model,
        anomaly_types, summary, findings_by_service and risk_matrix are already in final-report
        format; statistics adds extra context."""
        return await call(f"{_org(organization_id)}/summary")

    @server.tool()
    async def list_findings(
        organization_id: OrgId,
        severity: Optional[Severity] = None,
        service: Optional[Service] = None,
        status: Optional[Status] = None,
        limit: PageLimit = config.DEFAULT_PAGE_LIMIT,
        offset: Offset = 0,
    ) -> Dict[str, Any]:
        """Security findings and misconfigurations, most severe first. Filters combine with AND.
        Response includes total/limit/offset for pagination."""
        return await call(
            f"{_org(organization_id)}/findings",
            {"severity": severity, "service": service, "status": status, "limit": limit, "offset": offset},
        )

    @server.tool()
    async def get_asset(organization_id: OrgId, asset_id: AssetId) -> Dict[str, Any]:
        """Full detail for one asset: configuration, exposure, data sensitivity, criticality, record count,
        related findings and anomalies, and failed/unknown security controls."""
        return await call(f"{_org(organization_id)}/assets/{quote(asset_id, safe='')}")

    @server.tool()
    async def query_auth_logs(
        organization_id: OrgId,
        username: Optional[str] = None,
        asset_id: OptAssetId = None,
        source_ip: Optional[str] = None,
        country: Optional[str] = None,
        outcome: Optional[Outcome] = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        limit: PageLimit = config.DEFAULT_PAGE_LIMIT,
        offset: Offset = 0,
    ) -> Dict[str, Any]:
        """Search authentication and access events (newest first). All filters combine with AND."""
        return await call(
            f"{_org(organization_id)}/auth-logs",
            {
                "username": username,
                "asset_id": asset_id,
                "source_ip": source_ip,
                "country": country,
                "outcome": outcome,
                "start_time": _iso(start_time),
                "end_time": _iso(end_time),
                "limit": limit,
                "offset": offset,
            },
        )

    @server.tool()
    async def top_risks(
        organization_id: OrgId,
        limit: Annotated[
            int,
            Field(ge=config.MIN_TOP_RISKS, le=config.MAX_TOP_RISKS, description="Number of top risks (5-7)"),
        ] = config.DEFAULT_TOP_RISKS,
    ) -> Dict[str, Any]:
        """Highest-priority risks (one per asset), ranked by the backend. `items` are in final-report format
        with business_impact and remediation left null for you to fill in (remediation_window is set);
        `scoring_details` (keyed by risk_id) explains the likelihood and impact factors. All numbers are
        authoritative: explain them, never recalculate or change them."""
        return await call(f"{_org(organization_id)}/risks", {"limit": limit})

    @server.tool()
    async def get_data_inventory(
        organization_id: OrgId,
        asset_id: OptAssetId = None,
        sensitivity: Optional[Sensitivity] = None,
        contains_pii: Optional[bool] = None,
        contains_financial_data: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Data assets with classification, sensitivity, record counts (null = unknown, not zero), PII and
        financial-data flags, storage location, exposure and business criticality."""
        items = await call(
            f"{_org(organization_id)}/data-inventory",
            {
                "asset_id": asset_id,
                "sensitivity": sensitivity,
                "contains_pii": contains_pii,
                "contains_financial_data": contains_financial_data,
            },
        )
        return {"organization_id": organization_id, "total": len(items), "items": items}

    @server.tool()
    async def detect_anomalies(
        organization_id: OrgId,
        anomaly_type: Optional[AnomalyType] = None,
        asset_id: OptAssetId = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
    ) -> Dict[str, Any]:
        """Run anomaly detection over authentication logs (new-country logins, impossible travel, off-hours
        admin activity, excessive failed logins, unusual data access). `items` are in final-report format;
        `evidence` (keyed by anomaly_id) lists confidence and supporting auth event IDs. Results are signals
        to investigate, not confirmed malicious activity."""
        return await call(
            f"{_org(organization_id)}/anomalies",
            {
                "anomaly_type": anomaly_type,
                "asset_id": asset_id,
                "start_time": _iso(start_time),
                "end_time": _iso(end_time),
            },
        )
