# AgentRed — Roadmap

## v0.1 (current)

- Offline mock backend + Ollama backend + **real LangGraph ReAct backend**
  (`--backend langgraph`).
- Four attack categories, deterministic generator (100/300/500 budgets).
- Sandboxed tool environment with a permission model.
- Monitoring, four detectors, scoring, Markdown/HTML/JSON reports.
- Pytest suite; runnable end to end with no model download.

## Near term

- **Live Ollama/LangGraph integration test** (skipped when Ollama is absent).
- **CI**: lint + pytest on push; packaged release to PyPI.
- **Richer attack library**: obfuscated payloads (base64, homoglyphs),
  multilingual injections, multi-turn / conversational attacks.

## Medium term

- **More detectors**: unsafe-content generation, goal hijacking, tool-argument
  tampering, excessive-agency detection.
- **Additional target adapters**: CrewAI, AutoGen, and a generic HTTP/function
  adapter so users can point AgentRed at any agent endpoint.
- **Baseline/benign runs** to measure false-positive rates of detectors.
- **Diff mode**: compare two assessments (before/after a mitigation).

## Longer term

- **Coverage-guided / adaptive attack generation** that learns which payloads
  work against a given agent and focuses budget there.
- **Report exports** (PDF), and a shareable HTML dashboard.
- **Benchmark suite** and a public leaderboard of agent configurations.

## Explicit non-goals

- Being an agent framework or a production runtime.
- Using paid or cloud LLM APIs at runtime.
- Performing real-world side effects (real email, real filesystem, network
  exfiltration). All actions remain sandboxed.
