# Handoff between Part A (backend) and Part B (reporting)

## 1. The data contract

`report_data.example.json` is the agreed shape. The backend's output must match
it field for field. Check any output with:

```python
from reporting import validate_contract
validate_contract(data)   # raises ContractError listing every problem
```

It checks that totals add up, every score equals its breakdown, every factor
matches `scoring_model`, risks are sorted, remediation windows follow severity,
and evidence refs to auth logs point at real anomalies.

## 2. Calling the report builder from the MCP tool

```python
from reporting import build_report

@mcp.tool()
def generate_report(format: str = "pptx",
                    executive_summary: str | None = None,
                    key_messages: list[str] | None = None,
                    correlated_story: str | None = None) -> str:
    """Build the assessment deck. Returns the file path."""
    data = build_report_data()          # Part A: produces the contract JSON as a dict
    narrative = {"executive_summary": executive_summary,
                 "key_messages": key_messages,
                 "correlated_story": correlated_story}
    return build_report(data, narrative, out_dir="output", fmt=format)
```

- Any narrative field left empty falls back to plain data-only wording.
- `NarrativeError` means the AI used a number not in the data or wrote too
  much. Return the error message to the AI so it can fix its text and retry.
- `fmt="pdf"` needs LibreOffice installed (`SOFFICE_CMD` overrides the path).

## 3. Rules

- Field names and structure in the example file change only by agreement.
- Scoring weights, anomaly rules and remediation windows live in the backend
  config, and are copied into `scoring_model` and `anomaly_types` in the output.
- Bump `scoring_model.version` when weights change.
