"""Part A + Part B together: build the deck from the real backend output and
check every slide, for each demo organisation."""

import pytest
from pptx import Presentation

from mcp_server.tools.security_tools import default_risk_text
from reporting import build_report, validate_contract
from reporting.metrics import allowed_numbers, unknown_numbers
from tests.test_report_numbers import chart_values, slide_texts


@pytest.mark.parametrize("org", ["org-001", "org-002"])
def test_real_backend_report_builds_and_every_number_traces_to_data(client, tmp_path, org):
    risks = client.get(f"/organizations/{org}/risks", params={"limit": 5}).json()["items"]
    annotations = [default_risk_text(r).model_dump() for r in risks]
    resp = client.post(f"/organizations/{org}/assessments",
                       json={"top_risks_limit": 5, "annotations": annotations})
    assert resp.status_code == 201
    data = resp.json()
    assert validate_contract(data) == []

    prs = Presentation(build_report(data, None, out_dir=tmp_path))
    allowed = allowed_numbers(data)
    for i, text in enumerate(slide_texts(prs), start=1):
        assert not unknown_numbers(text, allowed), f"{org} slide {i}"
    assert chart_values(prs)["chart_service"] == data["findings_by_service"]
