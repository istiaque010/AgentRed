# Sample assessment report

This folder is an **example of AgentRed's output**, so you can see what a scan
produces without running one. It was generated against the bundled example agent
([`../email_agent.yaml`](../email_agent.yaml)) with the offline `mock` backend:

```bash
agentred scan --config examples/email_agent.yaml --level standard --seed 0 \
  --out examples/sample-report
```

Contents:

| File | What it is |
|---|---|
| [`report.md`](report.md) | The Markdown report (renders on GitHub) |
| `report.html` | The styled HTML report (open in a browser; has a Save-as-PDF button) |
| `asr_by_category.svg` | Chart: Attack Success Rate by category |
| `severity_distribution.svg` | Chart: successful attacks by severity |
| `security_score.svg` | Chart: overall security score |
| `traces.json` | Machine-readable execution traces + findings |

> These files are illustrative output from a deterministic mock run — not a real
> model assessment, and not a safety guarantee. Regenerate any time with the
> command above.
