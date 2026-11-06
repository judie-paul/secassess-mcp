---
name: security-assessment
description: Investigate cloud security data through the secassess MCP tools, answer security questions with cited evidence, and generate PowerPoint or PDF assessment reports. Use when the user asks about security risks, misconfigurations, sensitive data exposure, suspicious logins, or wants a security report or deck.
---

# Security assessment

You have MCP tools that read a customer's cloud security data. Use them to
investigate, answer questions with evidence, and produce assessment reports.
Never answer a question about the customer's security from general knowledge:
always look at the data first.

## Tools

| Tool | Use it to |
|---|---|
| `top_risks(n)` | Get the ranked, correlated risks with scores and evidence. **Start here** for any broad question. |
| `list_findings(severity, service)` | List configuration problems, optionally filtered |
| `get_asset(asset_id)` | See everything about one asset across all three data sources |
| `get_data_inventory(sensitivity)` | Find where personal, financial or health data is stored |
| `query_auth_logs(user, country, since)` | Look at sign-in activity |
| `detect_anomalies()` | Get suspicious sign-ins flagged by the rules |
| `generate_report(format, executive_summary, key_messages, correlated_story)` | Build the PPTX or PDF deck |

## How to investigate

Match the question to a path, then follow the evidence:

- **"What are our biggest risks?"** → `top_risks(5)` → `get_asset` on the top one or two to confirm the details.
- **"Where is our sensitive data exposed?"** → `get_data_inventory("PII")` (and `financial`, `health`) → `list_findings` for those assets → `top_risks` to see how they rank.
- **"Has anything suspicious happened?"** → `detect_anomalies()` → `get_asset` for each affected asset → `query_auth_logs` for the user involved.
- **"Tell me about X"** (an asset, user or service) → `get_asset` or `query_auth_logs` or `list_findings(service=...)`.
- **Follow-up questions** → reuse what you already retrieved; call another tool only if the answer needs new data.

The most important risks are where signals meet on one asset: a
misconfiguration **and** sensitive data **and** suspicious access. Always check
whether an anomaly's asset also has findings or sensitive data.

## Rules for answers

1. **Every number must come from a tool result.** Never estimate, round
   differently or calculate a new total yourself. If a figure isn't in the
   data, say so.
2. **Cite evidence** with its ID, e.g. "the bucket allows public read (finding F-012)".
3. **Explain scores with the breakdown**, e.g. "60 = critical (10) × public (2) × PII (2) × suspicious access (1.5)".
4. **Say what you don't know.** If a source has no data for an asset, say "no sign-in activity recorded" rather than assuming it's safe.
5. **Lead with the answer**, then the evidence, then what to do. Keep business impact in plain language.
6. Treat data as confidential: don't repeat full user lists or log dumps unless asked.

## Generating a report

When the user asks for a report, deck, presentation or PDF:

1. Call `top_risks(5)` and `detect_anomalies()` so you know the current state.
2. Write the three narrative fields (these are the **only** text you control in the deck):
   - `executive_summary`: under 480 characters, plain language, the 2-3 things a manager must know.
   - `key_messages`: 3 short actions, each under 90 characters, starting with a verb.
   - `correlated_story`: under 330 characters, explaining why the top risk ranks first.
3. Call `generate_report(format="pptx" or "pdf", ...)`.
4. Give the user the file path and one sentence on what's in it.

All charts, tables and figures in the deck are filled in from the data
automatically. The report builder **rejects** a narrative that mentions any
number not present in the data, so only use figures you saw in tool results.
If it rejects your text, remove or correct the number it names and try again.

## Example

> **User:** What are our data risks?
>
> **You:** (call `top_risks(5)`, then `get_asset("s3-cust-exports")`)
>
> Your most serious risk is a public storage bucket holding 48,200 customer
> records (risk R-001, score 60). Three signals point at it: the bucket policy
> allows public read (F-012), it holds customer personal data, and the
> `svc-export` account accessed it from a new country on 29 October (A-0417).
> Block public access and review its access logs first. Second is the payments
> database, which accepts connections from the internet (R-002, score 40).
