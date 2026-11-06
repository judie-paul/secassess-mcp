"""MCP server: exactly seven tools, each calling the backend over HTTP."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server.client import BackendClient
from mcp_server.server import create_server
from mcp_server.tools.security_tools import TOOL_NAMES

pytestmark = pytest.mark.anyio

ORG = "org-001"


async def call(server, name, **arguments):
    result = await server.call_tool(name, arguments)
    assert result.is_error is False
    return result.structured_content["result"]


async def test_exactly_eight_tools(mcp):
    tools = await mcp.list_tools()
    assert sorted(t.name for t in tools) == sorted(TOOL_NAMES)
    assert len(tools) == 8
    assert all(t.description for t in tools)


async def test_get_organization_summary(mcp):
    data = await call(mcp, "get_organization_summary", organization_id=ORG)
    assert data["organisation"] == "Savanna Ridge Financial Ltd"
    assert data["summary"]["anomalies_detected"] == 9
    assert data["schema_version"] == "1.0"


async def test_list_findings_with_filters(mcp):
    data = await call(mcp, "list_findings", organization_id=ORG, severity="critical", limit=2)
    assert data["total"] == 4 and len(data["items"]) == 2
    assert all(f["severity"] == "critical" for f in data["items"])


async def test_get_asset(mcp):
    data = await call(mcp, "get_asset", organization_id=ORG, asset_id="a-iam-001")
    assert data["name"] == "ops-admin" and data["related_findings"]


async def test_query_auth_logs(mcp):
    data = await call(
        mcp, "query_auth_logs", organization_id=ORG, username="alice.wanjiru", country="Brazil",
        start_time="2026-11-04T00:00:00Z",
    )
    assert data["total"] == 2
    assert {e["source_ip"] for e in data["items"]} == {"203.0.113.77"}


async def test_top_risks(mcp):
    data = await call(mcp, "top_risks", organization_id=ORG, limit=7)
    assert data["returned"] == 7
    assert [r["risk_id"] for r in data["items"]] == [f"R-{i:03d}" for i in range(1, 8)]
    assert set(data["items"][0]["score_breakdown"]) == {"severity", "exposure", "data_sensitivity", "activity"}
    assert set(data["scoring_details"]) == {r["risk_id"] for r in data["items"]}


async def test_get_data_inventory(mcp):
    data = await call(mcp, "get_data_inventory", organization_id=ORG, contains_pii=True)
    assert data["total"] == len(data["items"]) > 0
    assert all(i["contains_pii"] for i in data["items"])


async def test_detect_anomalies(mcp):
    data = await call(mcp, "detect_anomalies", organization_id=ORG, anomaly_type="impossible_travel")
    assert data["total"] == 1 and data["items"][0]["user"] == "carol.mendes"
    assert data["evidence"][data["items"][0]["anomaly_id"]]["supporting_event_ids"]


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("top_risks", {"organization_id": ORG, "limit": 9}),
        ("top_risks", {"organization_id": ORG, "limit": 3}),
        ("list_findings", {"organization_id": ORG, "severity": "severe"}),
        ("list_findings", {"organization_id": ORG, "limit": 0}),
        ("get_asset", {"organization_id": ORG}),
        ("get_asset", {"organization_id": "../etc", "asset_id": "a-1"}),
        ("query_auth_logs", {"organization_id": ORG, "start_time": "yesterday"}),
        ("detect_anomalies", {"organization_id": ORG, "anomaly_type": "alien"}),
        ("get_data_inventory", {"organization_id": ORG, "sensitivity": "secret"}),
    ],
)
async def test_invalid_arguments_rejected_before_backend(name, arguments):
    def fail(request):  # any backend call would be a bug
        raise AssertionError(f"backend called: {request.url}")

    server = create_server(BackendClient("http://testserver", transport=httpx.MockTransport(fail)))
    with pytest.raises(ToolError):
        await server.call_tool(name, arguments)


async def test_backend_not_found_is_reported_gracefully(mcp):
    with pytest.raises(ToolError, match="HTTP 404 \\(not_found\\): Asset 'a-missing' was not found"):
        await mcp.call_tool("get_asset", {"organization_id": ORG, "asset_id": "a-missing"})


async def test_backend_unavailable_is_reported_gracefully():
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    server = create_server(BackendClient("http://127.0.0.1:9", transport=httpx.MockTransport(down)))
    with pytest.raises(ToolError, match="backend_unavailable"):
        await server.call_tool("get_organization_summary", {"organization_id": ORG})


async def test_backend_server_error_is_reported_gracefully():
    def broken(request):
        return httpx.Response(500, json={"error": {"code": "data_error", "message": "Invalid JSON in assets.json"}})

    server = create_server(BackendClient("http://testserver", transport=httpx.MockTransport(broken)))
    with pytest.raises(ToolError, match="HTTP 500 \\(data_error\\): Invalid JSON in assets.json"):
        await server.call_tool("top_risks", {"organization_id": ORG})


async def test_tools_call_expected_endpoints():
    seen = []

    def record(request):
        seen.append((request.url.path, dict(request.url.params)))
        body = [] if request.url.path.endswith("data-inventory") else {}
        return httpx.Response(200, json=body)

    server = create_server(BackendClient("http://testserver", transport=httpx.MockTransport(record)))
    await server.call_tool("get_organization_summary", {"organization_id": ORG})
    await server.call_tool("list_findings", {"organization_id": ORG, "service": "S3"})
    await server.call_tool("get_asset", {"organization_id": ORG, "asset_id": "a-s3-001"})
    await server.call_tool("query_auth_logs", {"organization_id": ORG, "outcome": "failure"})
    await server.call_tool("top_risks", {"organization_id": ORG})
    await server.call_tool("get_data_inventory", {"organization_id": ORG, "contains_pii": False})
    await server.call_tool("detect_anomalies", {"organization_id": ORG})
    paths = [p for p, _ in seen]
    assert paths == [
        f"/organizations/{ORG}/summary",
        f"/organizations/{ORG}/findings",
        f"/organizations/{ORG}/assets/a-s3-001",
        f"/organizations/{ORG}/auth-logs",
        f"/organizations/{ORG}/risks",
        f"/organizations/{ORG}/data-inventory",
        f"/organizations/{ORG}/anomalies",
    ]
    assert seen[1][1]["service"] == "S3"
    assert seen[3][1]["outcome"] == "failure"
    assert seen[4][1]["limit"] == "5"
    assert seen[5][1]["contains_pii"] == "false"


def test_mcp_package_does_not_read_data_files():
    """The MCP layer must go through HTTP; it may not import the repository or open files."""
    root = Path(__file__).resolve().parent.parent / "mcp_server"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", "") or ""
                names = [a.name for a in node.names]
                assert "data_access" not in module and not any("data_access" in n for n in names), path
                assert "services" not in module, path
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "open":
                pytest.fail(f"{path} opens a file")


async def test_tool_outputs_assemble_into_example_report(mcp):
    """Following the server instructions, tool outputs alone produce a report in the example format."""
    from tests.test_reports import EXAMPLE, assert_same_shape

    if EXAMPLE is None:
        pytest.skip("contracts/report_data.example.json not present")

    summary = await call(mcp, "get_organization_summary", organization_id=ORG)
    risks = await call(mcp, "top_risks", organization_id=ORG)
    anomalies = await call(mcp, "detect_anomalies", organization_id=ORG)
    report = {key: summary[key] for key in
              ("schema_version", "generated_at", "organisation", "scoring_model", "anomaly_types", "summary",
               "findings_by_service", "risk_matrix")}
    report["top_risks"] = [{**r, "business_impact": "...", "remediation": "..."} for r in risks["items"]]
    report["anomalies"] = anomalies["items"]
    assert_same_shape(report, EXAMPLE)

    from reporting import validate_contract

    assert validate_contract(report, raise_on_error=False) == []
