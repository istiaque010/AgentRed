"""AgentRed - an open-source red-teaming framework for AI agent security.

AgentRed is a *security assessment* tool. It runs controlled adversarial
attacks against a target AI agent and reports whether the agent can be
manipulated into unsafe behaviour (following injected instructions, calling
unauthorized tools, leaking secrets, or exposing its system prompt).

It is NOT an agent framework and does not deploy agents into production.
"""

__version__ = "0.1.2"

__all__ = ["__version__"]
