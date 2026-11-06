"""The generate_report MCP tool: backend data -> Part B deck builder."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from pptx import Presentation

import config
from mcp_server.tools.security_tools import default_risk_text

pytestmark = pytest.mark.anyio

ORG = "org-001"


@pytest.fixture(autouse=True)
def output_dir(tmp_path, monkeypatch):
    target = tmp_path / "output"
    monkeypatch.setattr(config, "REPORT_OUTPUT_DIR", target)
    return target


async def call(server, **arguments):
    result = await server.call_tool("generate_report", arguments)
    assert result.is_error is False
    return result.structured_content["result"]


async def top_risks(server, limit=5):
    result = await server.call_tool("top_risks", {"organization_id": ORG, "limit": limit})
    return result.structured_content["result"]["items"]


def deck_text(path: str) -> str:
    texts = []
    for slide in Presentation(path).slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                texts.append(shape.text_frame.text)
    return "\n".join(texts)


async def test_builds_deck_with_ai_text(mcp, output_dir):
    risks = await top_risks(mcp)
    notes = [
        {"risk_id": r["risk_id"], "business_impact": f"Impact for {r['risk_id']}.", "remediation": f"Fix {r['risk_id']}."}
        for r in risks
    ]
    data = await call(
        mcp,
        organization_id=ORG,
        risk_annotations=notes,
        executive_summary="Customer data is exposed and was accessed from an unusual location.",
        key_messages=["Close public database access", "Enforce MFA for administrators"],
        correlated_story="A public database holding customer data was read in bulk from a new country.",
    )
    path = Path(data["path"])
    assert path.parent == output_dir and path.suffix == ".pptx" and path.exists()
    assert data["ai_risk_text"] == [r["risk_id"] for r in risks]
    assert data["default_risk_text"] == []
    assert data["narrative_fields_supplied"] == ["correlated_story", "executive_summary", "key_messages"]
    text = deck_text(str(path))
    assert "Impact for R-001." in text and "Close public database access" in text


async def test_missing_text_falls_back_to_data_only_wording(mcp):
    data = await call(mcp, organization_id=ORG)
    assert data["ai_risk_text"] == []
    assert data["default_risk_text"] == data["top_risks"]
    assert "a-rds-001" in deck_text(data["path"])


async def test_partial_annotations_mix_ai_and_default_text(mcp):
    risks = await top_risks(mcp)
    note = {"risk_id": risks[0]["risk_id"], "business_impact": "AI impact.", "remediation": "AI fix."}
    data = await call(mcp, organization_id=ORG, risk_annotations=[note])
    assert data["ai_risk_text"] == [risks[0]["risk_id"]]
    assert data["default_risk_text"] == [r["risk_id"] for r in risks[1:]]


async def test_seven_risk_report(mcp):
    data = await call(mcp, organization_id=ORG, top_risks_limit=7)
    assert len(data["top_risks"]) == 7


async def test_small_org_with_few_risks(mcp):
    data = await call(mcp, organization_id="org-002")
    assert 0 < len(data["top_risks"]) < config.MIN_TOP_RISKS
    assert Path(data["path"]).exists()


async def test_narrative_with_invented_number_is_rejected(mcp):
    with pytest.raises(ToolError, match="numbers not found in the data") as excinfo:
        await mcp.call_tool(
            "generate_report",
            {"organization_id": ORG, "executive_summary": "We found 987654 exposed records."},
        )
    assert "987654" in str(excinfo.value)
    assert "call generate_report again" in str(excinfo.value)


@pytest.mark.parametrize(
    "arguments",
    [
        {"organization_id": ORG, "format": "docx"},
        {"organization_id": ORG, "key_messages": ["a", "b", "c", "d"]},
        {"organization_id": ORG, "key_messages": ["x" * 91]},
        {"organization_id": ORG, "executive_summary": "x" * 481},
        {"organization_id": ORG, "top_risks_limit": 8},
        {"organization_id": ORG, "risk_annotations": [{"risk_id": "R-001", "business_impact": "x",
                                                       "remediation": "y", "score": 99}]},
        {"organization_id": "../etc"},
    ],
)
async def test_invalid_arguments_rejected(mcp, arguments, output_dir):
    with pytest.raises(ToolError):
        await mcp.call_tool("generate_report", arguments)
    assert not output_dir.exists()


async def test_annotation_for_unknown_risk_rejected(mcp):
    note = {"risk_id": "R-999", "business_impact": "x", "remediation": "y"}
    with pytest.raises(ToolError, match="R-999"):
        await mcp.call_tool("generate_report", {"organization_id": ORG, "risk_annotations": [note]})


async def test_duplicate_annotations_rejected(mcp):
    note = {"risk_id": "R-001", "business_impact": "x", "remediation": "y"}
    with pytest.raises(ToolError, match="more than once"):
        await mcp.call_tool("generate_report", {"organization_id": ORG, "risk_annotations": [note, note]})


async def test_unknown_organization_reported_gracefully(mcp):
    with pytest.raises(ToolError, match="HTTP 404"):
        await mcp.call_tool("generate_report", {"organization_id": "org-999"})


async def test_report_is_reproducible(mcp):
    # Same definition of "identical" as Part B's test_same_input_gives_identical_deck: slide text and
    # chart values (raw .pptx bytes differ only by zip timestamps).
    from tests.test_report_numbers import chart_values, slide_texts

    first = Presentation((await call(mcp, organization_id=ORG))["path"])
    first_texts, first_charts = slide_texts(first, skip_chrome=False), chart_values(first)
    second = Presentation((await call(mcp, organization_id=ORG))["path"])
    assert slide_texts(second, skip_chrome=False) == first_texts
    assert chart_values(second) == first_charts


def test_default_risk_text_uses_only_backend_values():
    risk = {
        "risk_id": "R-002", "asset_id": "a-x", "service": "S3", "title": "Bucket is public",
        "exposure": "public", "data_sensitivity": "PII", "record_count": None, "anomalous_access": True,
        "evidence": [{"source": "findings", "ref": "FND-0001", "detail": "d"},
                     {"source": "findings", "ref": "FND-0002", "detail": "d"}],
    }
    text = default_risk_text(risk)
    assert text.business_impact == (
        "S3 asset a-x holds PII data and is reachable from the internet. Suspicious access to it was detected."
    )
    assert text.remediation == (
        "Resolve finding FND-0001: bucket is public. Then address FND-0002. Review the flagged access."
    )
