"""Shared pytest fixtures."""

from pathlib import Path

import pytest

from agentred.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = REPO_ROOT / "examples" / "email_agent.yaml"


@pytest.fixture
def config():
    return load_config(EXAMPLE_CONFIG)
