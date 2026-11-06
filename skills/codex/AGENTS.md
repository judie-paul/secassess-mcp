# AGENTS.md: secassess-mcp

Guidance for OpenAI Codex (and other coding agents) working in this repo or
using its MCP server.

## Using the MCP server from Codex

Add the server to `~/.codex/config.toml`:

```toml
[mcp_servers.secassess]
command = "python"
args = ["-m", "mcp_server.server"]
env = { PYTHONPATH = "/path/to/secassess-mcp" }
```

Then follow the same workflow as `skills/claude/SKILL.md`:

- Every tool takes `organization_id` (e.g. `org-001`).
- Start broad questions with `get_organization_summary` or `top_risks`, then drill in with `get_asset`.
- Every number in an answer must come from a tool result; cite evidence IDs (e.g. FND-0027).
- Explain scores with their breakdown (severity × exposure × data sensitivity × activity).
- For a report, write `executive_summary` (<480 chars), 1-3 `key_messages` (<90 chars each),
  `correlated_story` (<330 chars) and `risk_annotations` (business_impact and remediation per
  top risk, <400 chars each), then call `generate_report`. The builder rejects any number in
  that text that is not in the data.

## Working on the code

| Folder | What it is | Owner |
|---|---|---|
| `data/`, `api/`, `mcp_server/`, `analysis/` | Sample data, REST API, MCP tools, scoring | Part A |
| `reporting/`, `skills/`, `examples/` | Deck builder, AI skills, sample output | Part B |
| `contracts/` | The JSON passed from Part A to Part B | Shared: change only with agreement |

Commands:

```bash
pip install -e ".[dev]"
pytest -q                                   # all tests must pass
python -m reporting contracts/report_data.example.json \
    --narrative contracts/narrative.example.json --out output --fmt pptx
```

Rules:

- Never hard-code a number on a slide. Figures come from the contract JSON or
  `reporting/metrics.derive()`; anything else fails `tests/test_report_numbers.py`.
- Colours and fonts live only in `reporting/template/theme.py`.
- Scoring weights live only in the backend config and arrive via `scoring_model`.
- AI-written text (narrative and per-risk business_impact/remediation) is checked for
  numbers, never trusted as a source of them.
- If you change the contract shape, update `contracts/report_data.example.json`,
  `reporting/contract.py` and the tests in the same change.
