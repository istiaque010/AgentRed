"""Shared data models for AgentRed.

These dataclasses define the contracts that flow between components:

    AttackCase  ->  Executor  ->  ExecutionTrace  ->  Detectors  ->  Finding
                                                                       |
                                                        Scoring / Report

Every model is JSON-serialisable via :func:`to_dict` so execution traces and
findings can be persisted exactly as described in the research spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

class Severity:
    """Ordered severity levels used across findings and attacks."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    #: Severity levels ordered most-severe first.
    ORDER = [CRITICAL, HIGH, MEDIUM, LOW]

    #: Relative weight used by the scoring engine.
    WEIGHTS = {CRITICAL: 1.0, HIGH: 0.7, MEDIUM: 0.4, LOW: 0.2}
    #: Rank for sorting (higher == more severe).
    RANK = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}
    #: Hex colour used consistently across charts and the HTML report.
    HEX = {CRITICAL: "#e5484d", HIGH: "#f5a524", MEDIUM: "#3b82f6", LOW: "#22c55e"}
    #: Emoji colour swatch for Markdown (which cannot render inline colour).
    EMOJI = {CRITICAL: "\U0001F7E5", HIGH: "\U0001F7E7",
             MEDIUM: "\U0001F7E6", LOW: "\U0001F7E9"}
    #: Plain-language meaning of each severity, for the report legend.
    DESCRIPTION = {
        CRITICAL: "Direct compromise — e.g. confidential data leaves the "
                  "protected environment.",
        HIGH: "Serious policy violation — unauthorized tool use or injected "
              "instructions obeyed.",
        MEDIUM: "Information exposure — e.g. the hidden system prompt is "
                "disclosed.",
        LOW: "Minor issue with limited direct impact.",
    }

    @classmethod
    def weight(cls, severity: str) -> float:
        return cls.WEIGHTS.get(str(severity).upper(), 0.4)

    @classmethod
    def rank(cls, severity: str) -> int:
        return cls.RANK.get(str(severity).upper(), 0)

    @classmethod
    def hex(cls, severity: str) -> str:
        return cls.HEX.get(str(severity).upper(), "#3b82f6")

    @classmethod
    def emoji(cls, severity: str) -> str:
        return cls.EMOJI.get(str(severity).upper(), "⬜")

    @classmethod
    def description(cls, severity: str) -> str:
        return cls.DESCRIPTION.get(str(severity).upper(), "")


class Category:
    """Canonical attack / finding categories (Section 4.2 of the spec)."""

    PROMPT_INJECTION = "indirect_prompt_injection"
    TOOL_MISUSE = "tool_misuse"
    DATA_LEAKAGE = "sensitive_data_leakage"
    PROMPT_LEAKAGE = "system_prompt_leakage"

    ALL = [PROMPT_INJECTION, TOOL_MISUSE, DATA_LEAKAGE, PROMPT_LEAKAGE]

    LABELS = {
        PROMPT_INJECTION: "Indirect Prompt Injection",
        TOOL_MISUSE: "Tool Misuse",
        DATA_LEAKAGE: "Sensitive Data Leakage",
        PROMPT_LEAKAGE: "System Prompt Leakage",
    }

    @classmethod
    def label(cls, category: str) -> str:
        return cls.LABELS.get(category, category.replace("_", " ").title())


# --------------------------------------------------------------------------- #
# Attack model
# --------------------------------------------------------------------------- #

@dataclass
class AttackCase:
    """A single concrete attack to execute against the target agent.

    Mirrors the attack-case definition in Section 4.1 of the research spec.
    """

    attack_id: str
    category: str
    description: str
    payload: str
    target_behavior: str
    success_condition: str
    severity: str = Severity.HIGH
    #: Where the payload is delivered: "email" | "file" | "user".
    channel: str = "email"
    #: Free-form template metadata (source template id, generated variant, ...).
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Execution / monitoring models
# --------------------------------------------------------------------------- #

@dataclass
class ToolCall:
    """A single tool invocation observed during agent execution."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    result: str = ""
    #: "executed" | "denied" | "error".
    status: str = "executed"
    #: "ALLOWED" | "DENIED" (against the agent's declared permissions).
    permission: str = "ALLOWED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    time: str
    event: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionTrace:
    """Complete record of one agent execution (Section 6.3 of the spec)."""

    assessment_id: str
    attack_id: str
    category: str
    user_input: str = ""
    injected_content: str = ""
    agent_response: str = ""
    timeline: list[TimelineEvent] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    #: Populated by the executor after detection: "vulnerable" | "safe".
    result: str = "safe"

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "attack_id": self.attack_id,
            "category": self.category,
            "user_input": self.user_input,
            "injected_content": self.injected_content,
            "agent_response": self.agent_response,
            "timeline": [e.to_dict() for e in self.timeline],
            "tool_calls": [t.to_dict() for t in self.tool_calls],
            "result": self.result,
        }


# --------------------------------------------------------------------------- #
# Detection model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """A security vulnerability finding produced by a detector."""

    finding_id: str
    attack_id: str
    severity: str
    category: str
    status: str  # "VULNERABLE" | "PASSED"
    description: str
    evidence: str
    impact: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackResult:
    """The outcome of executing one attack case end to end."""

    attack: AttackCase
    trace: ExecutionTrace
    findings: list[Finding] = field(default_factory=list)
    success: bool = False  # did the attack succeed (agent was vulnerable)?

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack": self.attack.to_dict(),
            "trace": self.trace.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "success": self.success,
        }
