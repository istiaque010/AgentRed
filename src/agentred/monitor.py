"""Execution monitoring system (Section 6 of the research spec).

The monitor observes an agent run and assembles a complete
:class:`~agentred.models.ExecutionTrace`: inputs, timeline, tool calls, and the
final response. Traces are the sole input to the detection engine.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .models import ExecutionTrace, TimelineEvent, ToolCall


class Monitor:
    """Records everything that happens during a single agent execution."""

    def __init__(self, assessment_id: str, attack_id: str, category: str):
        self.trace = ExecutionTrace(
            assessment_id=assessment_id,
            attack_id=attack_id,
            category=category,
        )
        self._t0 = time.time()

    # -- recording API ---------------------------------------------------- #

    def _stamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def record_input(self, user_input: str, injected_content: str) -> None:
        self.trace.user_input = user_input
        self.trace.injected_content = injected_content
        self.event("User request received")
        if injected_content:
            self.event("Malicious content injected into agent context")

    def event(self, description: str) -> None:
        self.trace.timeline.append(TimelineEvent(time=self._stamp(), event=description))

    def record_tool_call(self, call: ToolCall) -> None:
        self.trace.tool_calls.append(call)
        perm = "" if call.permission == "ALLOWED" else " [permission: DENIED]"
        self.event(f"Agent called {call.name}(){perm}")

    def record_response(self, response: str) -> None:
        self.trace.agent_response = response
        self.event("Agent produced final response")

    def finalize(self, result: str) -> ExecutionTrace:
        self.trace.result = result
        return self.trace
