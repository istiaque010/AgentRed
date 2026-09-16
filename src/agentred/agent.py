"""Target AI agent execution (Phases 1-2 of the spec).

The agent is modelled as a small state graph, mirroring the LangGraph
``perceive -> decide -> act`` control flow described in Section 2.2:

    ingest -> [ model -> tools ]*  -> respond

``model`` asks the LLM backend for the next step; if it returns tool calls we
run them through the sandboxed :class:`~agentred.tools.ToolEnvironment`, feed
the results back, and loop; otherwise we finish with the agent's answer.

The graph runner is intentionally self-contained (no heavyweight framework
dependency) so a scan runs offline. A drop-in LangGraph adapter is a planned
extension - see docs/roadmap.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import AgentConfig
from .llm import LLMBackend, MockBackend
from .monitor import Monitor
from .models import ExecutionTrace
from .tools import ToolEnvironment


@dataclass
class AgentRunResult:
    trace: ExecutionTrace
    response: str


class TargetAgent:
    """A tool-using agent under test."""

    def __init__(
        self,
        config: AgentConfig,
        backend: LLMBackend,
        env: ToolEnvironment,
        max_steps: int = 6,
    ):
        self.config = config
        self.backend = backend
        self.env = env
        self.max_steps = max_steps

    def prepare(self, attack_id: str, injected_directive: str) -> None:
        """Per-attack setup hook. Seeds the mock backend for reproducibility."""
        if isinstance(self.backend, MockBackend):
            self.backend.bind_attack(attack_id, injected_directive)

    def run(self, task: str, monitor: Monitor) -> AgentRunResult:
        """Execute the agent on ``task``, recording everything via ``monitor``."""
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.config.rendered_system_prompt},
            {"role": "user", "content": task},
        ]
        tools = self.env.schema
        final_text = ""

        for _ in range(self.max_steps):
            response = self.backend.chat(messages, tools=tools)

            if not response.has_tool_calls:
                final_text = response.content or ""
                break

            # Append the assistant's tool-call turn, then execute each call.
            messages.append(
                {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                }
            )
            for tc in response.tool_calls:
                call = self.env.call(tc.get("name", ""), tc.get("arguments", {}))
                monitor.record_tool_call(call)
                messages.append(
                    {"role": "tool", "name": call.name, "content": call.result}
                )
        else:
            # Loop exhausted without a final answer.
            final_text = final_text or "(agent stopped after max steps)"

        monitor.record_response(final_text)
        return AgentRunResult(trace=monitor.trace, response=final_text)
