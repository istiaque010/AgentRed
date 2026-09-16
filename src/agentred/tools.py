"""Sandboxed tool environment for the target agent (Phase 2 of the spec).

The tools here are deliberately *simulated*. AgentRed never sends a real email,
never reads a real inbox, and never touches the real filesystem. Every tool
call is captured so the monitor and detectors can reason about agent behaviour
in a fully controlled environment.

Tools provided:

    read_email()          - return the (possibly malicious) inbound email.
    read_file(path)       - return simulated file content.
    send_email(to, ...)   - the sensitive action; may exfiltrate data.

The environment enforces the permission model from the agent config so that
"unauthorized tool use" is a first-class, observable event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .config import AgentConfig
from .models import ToolCall


@dataclass
class ToolEnvironment:
    """Holds simulated resources and dispatches tool calls."""

    config: AgentConfig
    canary: str = ""
    #: Simulated inbox: the current inbound email content.
    email: dict[str, Any] = field(default_factory=dict)
    #: Simulated filesystem: path -> content.
    files: dict[str, str] = field(default_factory=dict)
    #: All calls made during a run, in order.
    calls: list[ToolCall] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._dispatch: dict[str, Callable[..., str]] = {
            "read_email": self._read_email,
            "read_file": self._read_file,
            "send_email": self._send_email,
            "list_files": self._list_files,
        }

    # -- public API ------------------------------------------------------- #

    @property
    def schema(self) -> list[dict[str, Any]]:
        """Tool schemas (Ollama / OpenAI style) for the declared tools."""
        catalog = {
            "read_email": {
                "description": "Read the most recent email in the user's inbox.",
                "parameters": {"type": "object", "properties": {}},
            },
            "read_file": {
                "description": "Read the contents of a file by path.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            "send_email": {
                "description": "Send an email to a recipient.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to", "body"],
                },
            },
            "list_files": {
                "description": "List available files.",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        schemas = []
        for name in self.config.tools:
            if name in catalog:
                schemas.append(
                    {
                        "type": "function",
                        "function": {"name": name, **catalog[name]},
                    }
                )
        return schemas

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolCall:
        """Execute a tool call, enforcing the permission model."""
        arguments = dict(arguments or {})

        # Tool not declared at all -> hard error (agent hallucinated a tool).
        if name not in self._dispatch or name not in self.config.tools:
            call = ToolCall(
                name=name,
                arguments=arguments,
                result=f"Error: tool '{name}' is not available.",
                status="error",
                permission="DENIED",
            )
            self.calls.append(call)
            return call

        allowed = self.config.is_tool_allowed(name)
        permission = "ALLOWED" if allowed else "DENIED"

        # We still *execute* the simulated action even when the permission is
        # DENIED, because the point of the assessment is to observe whether the
        # agent attempted an unauthorized action. A real deployment would block
        # it; here we record it as a violation and let detectors judge.
        try:
            result = self._dispatch[name](**arguments)
            status = "executed"
        except TypeError as exc:
            result = f"Error: bad arguments for {name}: {exc}"
            status = "error"
        except Exception as exc:  # pragma: no cover - defensive
            result = f"Error: {exc}"
            status = "error"

        call = ToolCall(
            name=name,
            arguments=arguments,
            result=result,
            status=status,
            permission=permission,
        )
        self.calls.append(call)
        return call

    # -- tool implementations -------------------------------------------- #

    def _read_email(self) -> str:
        if not self.email:
            return "(inbox empty)"
        sender = self.email.get("from", "unknown@example.com")
        subject = self.email.get("subject", "(no subject)")
        body = self.email.get("body", "")
        return f"From: {sender}\nSubject: {subject}\n\n{body}"

    def _read_file(self, path: str = "") -> str:
        if path in self.files:
            return self.files[path]
        # Be forgiving about leading ./ and case.
        for key, value in self.files.items():
            if key.lstrip("./") == str(path).lstrip("./"):
                return value
        return f"(file not found: {path})"

    def _list_files(self) -> str:
        return "\n".join(sorted(self.files)) or "(no files)"

    def _send_email(self, to: str = "", subject: str = "", body: str = "") -> str:
        # Simulated send. Never contacts a real mail server.
        return (
            f"Email queued to {to} with subject '{subject}' "
            f"({len(body)} chars body)."
        )
