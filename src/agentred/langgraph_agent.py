"""LangGraph-based target agent runner (Section 2.2 of the spec).

This is the "real framework" backend: it drives the target agent with a
LangGraph ReAct graph over a local model (via ``langchain_ollama.ChatOllama``),
instead of AgentRed's built-in graph runner.

Crucially, the tools handed to LangGraph are thin wrappers around AgentRed's
sandboxed :class:`~agentred.tools.ToolEnvironment`, so:

* every tool call is still recorded on the :class:`~agentred.monitor.Monitor`,
* the permission model is still enforced/observed, and
* no real email is sent and no real file is read.

LangGraph, LangChain, and langchain-ollama are optional dependencies. Install
them with ``pip install -e ".[langgraph]"``. Importing this module is safe even
when they are absent; the error is raised only when you actually run a scan
with ``--backend langgraph``.
"""

from __future__ import annotations

from typing import Any

from .agent import AgentRunResult
from .config import AgentConfig
from .monitor import Monitor
from .settings import DEFAULT_MODEL
from .tools import ToolEnvironment

# Lazy import markers - populated by _require_langgraph().
_LG: dict[str, Any] = {}


class LangGraphUnavailable(RuntimeError):
    """Raised when the LangGraph optional dependencies are not installed."""


def _require_langgraph() -> None:
    if _LG:
        return
    try:  # Imported lazily so the package works without these heavy deps.
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_core.tools import StructuredTool
        from langchain_ollama import ChatOllama
        from langgraph.prebuilt import create_react_agent
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise LangGraphUnavailable(
            "The LangGraph backend requires extra dependencies. Install them "
            'with `pip install -e ".[langgraph]"` (langgraph, langchain-core, '
            "langchain-ollama). A running Ollama server with the target model "
            "pulled is also required."
        ) from exc
    _LG.update(
        HumanMessage=HumanMessage,
        SystemMessage=SystemMessage,
        StructuredTool=StructuredTool,
        ChatOllama=ChatOllama,
        create_react_agent=create_react_agent,
    )


def _build_tools(env: ToolEnvironment, monitor: Monitor):
    """Wrap the sandboxed tools as LangChain StructuredTools.

    Each wrapper delegates to ``env.call`` (which enforces the permission model
    and records the call), reports it to the monitor, and returns the simulated
    result string back to the model.
    """
    _require_langgraph()
    StructuredTool = _LG["StructuredTool"]

    def _invoke(name: str, **kwargs) -> str:
        call = env.call(name, kwargs)
        monitor.record_tool_call(call)
        return call.result

    specs = {
        "read_email": dict(
            name="read_email",
            description="Read the most recent email in the user's inbox.",
            func=lambda: _invoke("read_email"),
        ),
        "read_file": dict(
            name="read_file",
            description="Read the contents of a file by path.",
            func=lambda path="": _invoke("read_file", path=path),
        ),
        "send_email": dict(
            name="send_email",
            description="Send an email to a recipient.",
            func=lambda to="", subject="", body="": _invoke(
                "send_email", to=to, subject=subject, body=body
            ),
        ),
        "list_files": dict(
            name="list_files",
            description="List available files.",
            func=lambda: _invoke("list_files"),
        ),
    }

    tools = []
    for tool_name in env.config.tools:
        if tool_name in specs:
            tools.append(StructuredTool.from_function(**specs[tool_name]))
    return tools


class LangGraphTargetAgent:
    """A target agent executed via a LangGraph ReAct graph over Ollama."""

    def __init__(
        self,
        config: AgentConfig,
        env: ToolEnvironment,
        model: str | None = None,
        host: str = "http://localhost:11434",
        max_steps: int = 8,
        temperature: float = 0.0,
    ):
        _require_langgraph()
        self.config = config
        self.env = env
        self.model = model or config.model or DEFAULT_MODEL
        self.host = host
        self.max_steps = max_steps
        self.temperature = temperature

    def prepare(self, attack_id: str, injected_directive: str) -> None:
        """No per-attack seeding needed for a real model backend."""
        return None

    def run(self, task: str, monitor: Monitor) -> AgentRunResult:
        HumanMessage = _LG["HumanMessage"]
        SystemMessage = _LG["SystemMessage"]
        ChatOllama = _LG["ChatOllama"]
        create_react_agent = _LG["create_react_agent"]

        llm = ChatOllama(
            model=self.model, base_url=self.host, temperature=self.temperature
        )
        tools = _build_tools(self.env, monitor)
        graph = create_react_agent(llm, tools)

        messages = [
            SystemMessage(content=self.config.rendered_system_prompt),
            HumanMessage(content=task),
        ]
        try:
            result = graph.invoke(
                {"messages": messages},
                config={"recursion_limit": self.max_steps * 2},
            )
        except Exception as exc:  # surface a helpful error to the CLI
            raise LangGraphUnavailable(
                f"LangGraph/Ollama execution failed: {exc}. Ensure Ollama is "
                f"running and the model '{self.model}' is pulled "
                f"(`ollama pull {self.model}`)."
            ) from exc

        final = ""
        for msg in reversed(result.get("messages", [])):
            content = getattr(msg, "content", "")
            if getattr(msg, "type", "") == "ai" and content:
                final = content if isinstance(content, str) else str(content)
                break

        monitor.record_response(final)
        return AgentRunResult(trace=monitor.trace, response=final)
