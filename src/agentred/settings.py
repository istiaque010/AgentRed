"""AgentRed tunable defaults — EDIT HERE.

This is the single place to change AgentRed's built-in default settings. Every
value here is a fallback: it can still be overridden per run (CLI flags) or per
agent (the agent YAML), but these are the numbers used when nothing else is set.

    Precedence for attack budget:  --budget flag  >  YAML `levels:`  >  here.
    Precedence for the model:      --model flag   >  YAML `model:`    >  here.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Attack budget per scan level (how many attacks each level runs).
# Change these numbers to tune the defaults for everyone.
# --------------------------------------------------------------------------- #

BASIC_BUDGET = 200      # `--level basic`    : fast check during development
STANDARD_BUDGET = 300   # `--level standard` : pre-deployment assessment
DEEP_BUDGET = 500       # `--level deep`     : comprehensive security review

#: Assembled mapping used by the engine. Add a new level here (and to the CLI
#: `--level` choices in cli.py) if you want more than these three.
LEVEL_BUDGETS = {
    "basic": BASIC_BUDGET,
    "standard": STANDARD_BUDGET,
    "deep": DEEP_BUDGET,
}

# --------------------------------------------------------------------------- #
# Target model default (used when the agent YAML sets no `model:` and no
# --model flag is given). Any model available in your Ollama install.
# --------------------------------------------------------------------------- #

DEFAULT_MODEL = "qwen2.5:7b"

# --------------------------------------------------------------------------- #
# Offline mock backend: how easily the simulated agent is manipulated (0..1).
# Higher = more vulnerable. Overridable per agent via `mock.susceptibility`.
# --------------------------------------------------------------------------- #

DEFAULT_MOCK_SUSCEPTIBILITY = 0.35
