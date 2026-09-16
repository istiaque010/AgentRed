# AgentRed — Architecture

AgentRed is a pipeline that turns an agent configuration into a security
assessment report. Each stage has one responsibility and a typed contract
(dataclasses in `agentred/models.py`).

## Pipeline

```
 agent.yaml
     │  config.load_config()
     ▼
 AgentConfig ──────────────────────────────────────────────┐
     │                                                      │ (permissions,
     │                                                      │  canary, prompt)
 Attack Library (data/attacks/*.yaml)                       │
     │  AttackLibrary.load()                                │
     ▼                                                      │
 AttackTemplate[]                                           │
     │  attack_generator.generate(level)                    │
     ▼                                                      │
 AttackCase[] ──────────────┐                               │
                            │                               │
                    Executor.run_case()  ◀──────────────────┘
                            │
        inject payload ─▶ ToolEnvironment (sandbox)
                            │
                    TargetAgent.run()  ◀── LLMBackend (mock | ollama)
                            │
                        Monitor
                            ▼
                     ExecutionTrace (JSON)
                            │  run_detectors()
                            ▼
                      Finding[]  ─▶ AttackResult
                            │  scoring.score()
                            ▼
                       Assessment (ASR, score, risk)
                            │  report.write_reports()
                            ▼
                report.md · report.html · traces.json
```

## Components

| Module | Responsibility |
|---|---|
| `config.py` | Parse `agent.yaml` into `AgentConfig`; encode the permission model. |
| `attacks.py` | Load attack templates grouped by category. |
| `attack_generator.py` | Expand templates into a deterministic, budget-sized `AttackCase[]`. |
| `tools.py` | Sandboxed `ToolEnvironment`; enforce/observe permissions. |
| `llm.py` | `LLMBackend` abstraction: `MockBackend` (offline) and `OllamaBackend`. |
| `agent.py` | `TargetAgent` — a LangGraph-shaped state graph running the agent loop. |
| `monitor.py` | Assemble the `ExecutionTrace` (timeline, tool calls, response). |
| `executor.py` | Inject payloads, run the agent, run detectors, produce `AttackResult`. |
| `detectors.py` | Four single-purpose detectors → `Finding[]`. |
| `scoring.py` | Aggregate results into an `Assessment`. |
| `report.py` | Render Markdown/HTML/JSON from templates. |
| `cli.py` | `agentred` command-line interface. |

## The target-agent loop

`TargetAgent.run()` executes a bounded graph:

```
ingest ─▶ [ model ─▶ tools ]*  ─▶ respond
```

- **ingest** builds the message list (system prompt + user task).
- **model** asks the backend for the next step (tool calls or a final answer).
- **tools** runs each requested call through the sandbox and feeds results back.
- The loop is bounded by `max_steps` to guarantee termination.

## Design principles

- **Offline-first / no paid APIs.** Target agents run on a local model via
  Ollama or the built-in offline mock backend — no external inference services.
- **Deterministic.** Generation and the mock backend are seeded.
- **Separation of instructions and data.** The whole tool exists to test what
  happens when an agent fails to keep them separate.
