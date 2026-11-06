"""Every figure in the deck must come from the data.

These tests open the generated .pptx and read it back, the same way a client
would, so they check what is actually on the slides rather than what the code
meant to put there.
"""

import pytest
from pptx import Presentation

from reporting.build_pptx import NarrativeError, build_report
from reporting.metrics import allowed_numbers, derive, format_int, unknown_numbers


def _shapes(container):
    for shp in container.shapes:
        if shp.shape_type == 6:  # group
            yield from _shapes(shp)
        else:
            yield shp


def slide_texts(prs, skip_chrome=True):
    """Text per slide, excluding footer/page-number chrome."""
    out = []
    for slide in prs.slides:
        parts = []
        for shp in _shapes(slide):
            if skip_chrome and shp.name.startswith("chrome_"):
                continue
            if shp.has_text_frame:
                parts.append(shp.text_frame.text)
            if getattr(shp, "has_table", False) and shp.has_table:
                for row in shp.table.rows:
                    parts.extend(c.text for c in row.cells)
        out.append("\n".join(parts))
    return out


def chart_values(prs):
    out = {}
    for slide in prs.slides:
        for shp in _shapes(slide):
            if getattr(shp, "has_chart", False) and shp.has_chart:
                plot = shp.chart.plots[0]
                out[shp.name] = dict(zip(plot.categories, plot.series[0].values))
    return out


@pytest.fixture
def deck(data, narrative, tmp_path):
    path = build_report(data, narrative, out_dir=tmp_path)
    return Presentation(path)


def test_deck_has_twelve_slides(deck):
    assert len(deck.slides) == 12


def test_every_number_on_every_slide_comes_from_the_data(deck, data):
    allowed = allowed_numbers(data)
    for i, text in enumerate(slide_texts(deck), start=1):
        bad = unknown_numbers(text, allowed)
        assert not bad, f"slide {i} shows numbers not in the data: {sorted(bad)}"


def test_summary_tiles_match_the_data(deck, data):
    s = data["summary"]
    m = derive(data)
    shapes = {shp.name: shp.text_frame.text for shp in deck.slides[1].shapes if shp.has_text_frame}
    assert shapes["tile_value_0"] == format_int(s["total_findings"])
    assert shapes["tile_value_1"] == format_int(m["critical_high"])
    assert shapes["tile_value_2"] == f"{s['sensitive_assets_exposed']} of {s['sensitive_assets']}"
    assert shapes["tile_value_3"] == format_int(s["anomalies_detected"])


def test_chart_values_match_the_data(deck, data):
    charts = chart_values(deck)
    sev = {k.capitalize(): v for k, v in data["summary"]["by_severity"].items()}
    assert charts["chart_severity"] == sev
    assert charts["chart_service"] == data["findings_by_service"]


def test_score_on_each_risk_slide_matches_the_data(deck, data):
    for slide, risk in zip(list(deck.slides)[6:9], data["top_risks"]):
        score = next(s for s in slide.shapes if s.name == "score_value").text_frame.text
        assert float(score) == risk["score"]
        title = next(s for s in slide.shapes if s.name == "title").text_frame.text
        assert title == risk["title"]


def test_heatmap_cells_match_the_risk_matrix(deck, data):
    cells = {s.name: s.text_frame.text.split("\n")[0] for s in deck.slides[3].shapes
             if s.name.startswith("heat_cell_")}
    for c in data["risk_matrix"]:
        assert cells[f"heat_cell_{c['likelihood']}_{c['impact']}"] == str(c["count"])


def test_narrative_with_invented_number_is_rejected(data, narrative, tmp_path):
    narrative["executive_summary"] += " About 97 servers are affected."
    with pytest.raises(NarrativeError, match="97"):
        build_report(data, narrative, out_dir=tmp_path)


def test_overlong_narrative_is_rejected(data, narrative, tmp_path):
    narrative["key_messages"] = ["x" * 200]
    with pytest.raises(NarrativeError, match="under"):
        build_report(data, narrative, out_dir=tmp_path)


def test_builds_without_ai_narrative(data, tmp_path):
    prs = Presentation(build_report(data, None, out_dir=tmp_path))
    allowed = allowed_numbers(data)
    for text in slide_texts(prs):
        assert not unknown_numbers(text, allowed)


def test_same_input_gives_identical_deck(data, narrative, tmp_path):
    a = Presentation(build_report(data, narrative, out_dir=tmp_path / "a"))
    b = Presentation(build_report(data, narrative, out_dir=tmp_path / "b"))
    assert slide_texts(a, skip_chrome=False) == slide_texts(b, skip_chrome=False)
    assert chart_values(a) == chart_values(b)


def test_fewer_than_three_risks_still_builds(data, tmp_path):
    data["top_risks"] = data["top_risks"][:1]
    prs = Presentation(build_report(data, None, out_dir=tmp_path))
    assert len(prs.slides) == 10
