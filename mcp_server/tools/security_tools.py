"""The eight MCP tools.

Seven read-only investigation tools each validate their arguments and call one
backend endpoint. `generate_report` sends the AI's per-risk text to the backend
(which validates it and returns the contract JSON), then builds the PPTX/PDF
deck with Part B's `reporting.build_report`. No tool reads data files directly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional
from urllib.parse import quote

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

import config
from mcp_server.client import BackendClient, BackendError
from reporting import ContractError, build_report
from reporting.build_pptx import NARRATIVE_LIMITS, NarrativeError
from reporting.metrics import lower_first

TOOL_NAMES = (
    "get_organization_summary",
    "list_findings",
    "get_asset",
    "query_auth_logs",
    "top_risks",
    "get_data_inventory",
    "detect_anomalies",
    "generate_report",
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


class RiskText(BaseModel):
    """AI-written text for one top risk (numbers and windows come from the backend)."""

    model_config = ConfigDict(extra="forbid")

    risk_id: str = Field(pattern=r"^R-\d{3}$", description="Top-risk ID from top_risks, e.g. R-001")
    business_impact: str = Field(min_length=1, max_length=400, description="Why this risk matters to the business")
    remediation: str = Field(min_length=1, max_length=400, description="Practical fix, in plain language")


def default_risk_text(risk: Dict[str, Any]) -> RiskText:
    """Plain, data-only wording for a top risk the AI did not describe."""
    records = f"{risk['record_count']:,} records of " if risk.get("record_count") is not None else ""
    reach = "reachable from the internet" if risk["exposure"] == "public" else "reachable internally"
    activity = " Suspicious access to it was detected." if risk["anomalous_access"] else ""
    findings = [e["ref"] for e in risk["evidence"] if e["source"] == "findings"]
    remediation = f"Resolve finding {findings[0]}: {lower_first(risk['title'])}."
    if len(findings) > 1:
        remediation += f" Then address {', '.join(findings[1:])}."
    if risk["anomalous_access"]:
        remediation += " Review the flagged access."
    return RiskText(
        risk_id=risk["risk_id"],
        business_impact=f"{risk['service']} asset {risk['asset_id']} holds {records}{risk['data_sensitivity']} "
        f"data and is {reach}.{activity}",
        remediation=remediation,
    )


def register_tools(server: MCPServer, client: BackendClient) -> None:
    async def call(path: str, params: Optional[Dict[str, Any]] = None, body: Any = None, method: str = "GET") -> Any:
        try:
            if method == "POST":
                return await client.post(path, body)
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

    @server.tool()
    async def generate_report(
        organization_id: OrgId,
        format: Literal["pptx", "pdf"] = "pptx",
        executive_summary: Annotated[
            Optional[str],
            Field(default=None, max_length=NARRATIVE_LIMITS["executive_summary"],
                  description="Plain-language summary for a manager (2-3 key points)"),
        ] = None,
        key_messages: Annotated[
            Optional[List[Annotated[str, Field(max_length=NARRATIVE_LIMITS["key_messages"])]]],
            Field(default=None, min_length=1, max_length=3, description="1-3 short actions, each starting with a verb"),
        ] = None,
        correlated_story: Annotated[
            Optional[str],
            Field(default=None, max_length=NARRATIVE_LIMITS["correlated_story"],
                  description="Why the top risk ranks first: how its signals connect"),
        ] = None,
        risk_annotations: Annotated[
            Optional[List[RiskText]],
            Field(default=None, description="business_impact and remediation for each top risk (by risk_id)"),
        ] = None,
        top_risks_limit: Annotated[
            int, Field(ge=config.MIN_TOP_RISKS, le=config.MAX_TOP_RISKS, description="Number of top risks (5-7)")
        ] = config.DEFAULT_TOP_RISKS,
    ) -> Dict[str, Any]:
        """Build the assessment deck (PPTX, or PDF via LibreOffice) and return the file path.

        All charts, tables and figures come from the backend. You control only the narrative
        (executive_summary, key_messages, correlated_story) and, per top risk, business_impact and
        remediation. Any you leave out fall back to plain data-only wording. The builder rejects text
        containing a number that is not in the data; if that happens, fix the number it names and retry."""
        risks = (await call(f"{_org(organization_id)}/risks", {"limit": top_risks_limit}))["items"]
        supplied = {a.risk_id: a for a in (risk_annotations or [])}
        if len(supplied) != len(risk_annotations or []):
            raise ToolError("risk_annotations contains the same risk_id more than once")
        unknown = sorted(set(supplied) - {r["risk_id"] for r in risks})
        if unknown:
            raise ToolError(f"risk_annotations reference risks that are not in the top risks: {', '.join(unknown)}")
        texts = [supplied.get(r["risk_id"]) or default_risk_text(r) for r in risks]
        report = await call(
            f"{_org(organization_id)}/assessments",
            body={"top_risks_limit": top_risks_limit, "annotations": [t.model_dump() for t in texts]},
            method="POST",
        )
        narrative = {
            "executive_summary": executive_summary,
            "key_messages": key_messages,
            "correlated_story": correlated_story,
        }
        out_dir = config.REPORT_OUTPUT_DIR
        filename = f"security_assessment_{organization_id}"
        try:
            path = await anyio.to_thread.run_sync(
                lambda: build_report(report, narrative, out_dir=out_dir, fmt=format, filename=filename)
            )
        except NarrativeError as exc:
            raise ToolError(f"{exc}\nFix the text and call generate_report again.") from exc
        except ContractError as exc:
            raise ToolError(f"Backend data failed the report contract check: {exc}") from exc
        except (OSError, RuntimeError) as exc:
            hint = " PDF export needs LibreOffice (set SOFFICE_CMD)." if format == "pdf" else ""
            raise ToolError(f"Report build failed: {exc}.{hint}") from exc
        return {
            "path": str(path),
            "format": format,
            "organisation": report["organisation"],
            "top_risks": [r["risk_id"] for r in report["top_risks"]],
            "ai_risk_text": sorted(supplied),
            "default_risk_text": sorted(r["risk_id"] for r in risks if r["risk_id"] not in supplied),
            "narrative_fields_supplied": sorted(k for k, v in narrative.items() if v),
        }
