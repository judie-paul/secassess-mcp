"""MCP server exposing seven security investigation tools plus generate_report.

Run with:  python -m mcp_server.server                     (stdio, launched by an MCP client)
      or:  python -m mcp_server.server --transport http --port 8001
           (long-running streamable HTTP server at http://127.0.0.1:8001/mcp)
The FastAPI backend must be running (see SECURITY_API_URL).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # allow `python mcp_server/server.py` from any directory
    sys.path.insert(0, str(ROOT))

from mcp.server.mcpserver import MCPServer  # noqa: E402

import config  # noqa: E402
from mcp_server.client import BackendClient  # noqa: E402
from mcp_server.tools.security_tools import register_tools  # noqa: E402

INSTRUCTIONS = f"""
You are investigating an organization's cloud security posture through a backend that performs all
calculations deterministically.

Workflow for an assessment:
1. get_organization_summary for context, then top_risks for the ranked risks.
2. For each top risk: get_asset, list_findings, query_auth_logs (where relevant), detect_anomalies,
   get_data_inventory, and check every evidence reference the risk cites.
3. Explain each risk, its business impact, and practical remediation.
4. For a deck, call generate_report with risk_annotations (business_impact and remediation for each
   top risk) and the narrative: executive_summary (under 480 characters), 1-3 key_messages (each
   under 90 characters, starting with a verb) and correlated_story (under 330 characters, why the
   top risk ranks first). Only use numbers you saw in tool results; the builder rejects any other
   number and names it, so fix that number and call generate_report again. Give the user the path.

Final report format (contracts/report_data.example.json). Output exactly one JSON object with these
keys in this order, copying backend values verbatim:
- schema_version, generated_at, organisation, scoring_model, anomaly_types, summary,
  findings_by_service, risk_matrix: copy from get_organization_summary.
- top_risks: copy every item from top_risks unchanged, filling in only business_impact (string) and
  remediation (string). remediation_window is already set by the backend from severity.
- anomalies: copy the items from detect_anomalies (called with no filters) unchanged.
Do not add, rename or drop keys.

Rules:
- Likelihood, impact, risk score, severity, rank and remediation window come from the backend and
  are authoritative. Never calculate, invent or alter them. You may explain them and point out
  low-confidence factors. Remediation windows follow severity: {", ".join(f"{k} {v}" for k, v in config.REMEDIATION_WINDOW_BY_SEVERITY.items())}.
- Anomalies are signals, not proof of compromise. Report missing or contradictory evidence as
  uncertainty instead of filling gaps.
""".strip()


def create_server(client: Optional[BackendClient] = None) -> MCPServer:
    server = MCPServer(name="security-assessment", instructions=INSTRUCTIONS, version=config.API_VERSION)
    register_tools(server, client or BackendClient())
    return server


def main(argv: Optional[list] = None) -> None:
    parser = argparse.ArgumentParser(description="Security assessment MCP server")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args(argv)
    server = create_server()
    if args.transport == "http":
        server.run("streamable-http", host=args.host, port=args.port)
    else:
        server.run()


if __name__ == "__main__":
    main()
