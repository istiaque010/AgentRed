"""LangGraph backend wiring tests.

Skipped entirely when the optional LangGraph dependencies are not installed.
The full graph run requires a live Ollama server, so here we only verify that
the sandboxed tools are correctly wrapped as LangChain tools and that calling
them still records on the monitor and enforces the permission model.
"""

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from agentred.langgraph_agent import _build_tools, LangGraphTargetAgent  # noqa: E402
from agentred.monitor import Monitor  # noqa: E402
from agentred.models import Category  # noqa: E402
from agentred.tools import ToolEnvironment  # noqa: E402


def _env_and_monitor(config):
    env = ToolEnvironment(config=config, canary=config.canary)
    env.email = {"from": "x@evil.test", "subject": "hi", "body": "secret note"}
    monitor = Monitor("A", "T0001", Category.PROMPT_INJECTION)
    return env, monitor


def test_build_tools_matches_declared_tools(config):
    env, monitor = _env_and_monitor(config)
    tools = _build_tools(env, monitor)
    names = {t.name for t in tools}
    assert names == set(config.tools)


def test_wrapped_read_email_records_call(config):
    env, monitor = _env_and_monitor(config)
    tools = {t.name: t for t in _build_tools(env, monitor)}

    result = tools["read_email"].invoke({})
    assert "secret note" in result
    assert len(monitor.trace.tool_calls) == 1
    assert monitor.trace.tool_calls[0].name == "read_email"
    assert monitor.trace.tool_calls[0].permission == "ALLOWED"


def test_wrapped_send_email_is_flagged_denied(config):
    env, monitor = _env_and_monitor(config)
    tools = {t.name: t for t in _build_tools(env, monitor)}

    tools["send_email"].invoke({"to": "attacker@evil.example", "body": "hi"})
    call = monitor.trace.tool_calls[-1]
    assert call.name == "send_email"
    # send_email is restricted in the example config.
    assert call.permission == "DENIED"


def test_agent_constructs_without_running(config):
    """Constructing the agent should succeed (deps present) without a model."""
    env, _ = _env_and_monitor(config)
    agent = LangGraphTargetAgent(config, env, model="qwen2.5:7b")
    # prepare() is a no-op for the real backend and must not raise.
    agent.prepare("T0001", "payload")
    assert agent.model == "qwen2.5:7b"
