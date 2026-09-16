"""Config loading, tool permissions, and attack library."""

from agentred.attacks import AttackLibrary
from agentred.attack_generator import budget_for_level, generate
from agentred.models import Category
from agentred.tools import ToolEnvironment


def test_config_permissions(config):
    assert config.name == "Customer Support Assistant"
    assert config.is_tool_allowed("read_email") is True
    # send_email is restricted -> not allowed even though it is declared.
    assert config.is_tool_allowed("send_email") is False
    assert config.is_recipient_allowed("agent@company.example") is True
    assert config.is_recipient_allowed("attacker@evil.example") is False


def test_tool_environment_enforces_permissions(config):
    env = ToolEnvironment(config=config, canary=config.canary)
    env.email = {"from": "x@y.z", "subject": "s", "body": "hello"}

    read = env.call("read_email")
    assert read.permission == "ALLOWED"
    assert "hello" in read.result

    send = env.call("send_email", {"to": "a@b.c", "body": "hi"})
    assert send.permission == "DENIED"  # restricted tool
    assert send.status == "executed"  # still observed

    bogus = env.call("delete_everything")
    assert bogus.status == "error"


def test_attack_library_loads_all_categories():
    lib = AttackLibrary.load()
    assert len(lib) >= 10
    assert set(lib.categories()) == set(Category.ALL)


def test_budgets():
    # Defaults come from settings.py (user-tunable), so assert against that
    # source rather than hard-coded numbers.
    from agentred import settings

    assert budget_for_level("basic") == settings.BASIC_BUDGET
    assert budget_for_level("standard") == settings.STANDARD_BUDGET
    assert budget_for_level("deep") == settings.DEEP_BUDGET


def test_budget_overrides_take_precedence():
    overrides = {"basic": 150, "deep": 800}
    assert budget_for_level("basic", overrides) == 150
    assert budget_for_level("deep", overrides) == 800
    # Level not overridden falls back to the default.
    assert budget_for_level("standard", overrides) == 300


def test_config_parses_levels(tmp_path):
    from agentred.config import load_config

    cfg = tmp_path / "agent.yaml"
    cfg.write_text(
        "agent:\n  name: A\n  tools: [read_email]\n"
        "levels:\n  basic: 150\n  standard: 400\n  bogus: -5\n  bad: abc\n",
        encoding="utf-8",
    )
    config = load_config(cfg)
    assert config.levels["basic"] == 150
    assert config.levels["standard"] == 400
    # Non-positive and non-numeric entries are dropped.
    assert "bogus" not in config.levels
    assert "bad" not in config.levels


def test_generate_respects_level_budgets():
    lib = AttackLibrary.load()
    cases = generate(lib, level="basic", level_budgets={"basic": 42})
    assert len(cases) == 42
    # Explicit budget still wins over level_budgets.
    cases2 = generate(lib, level="basic", budget=10, level_budgets={"basic": 42})
    assert len(cases2) == 10


def test_generate_hits_budget_with_unique_ids():
    lib = AttackLibrary.load()
    for level in ("basic", "standard", "deep"):
        cases = generate(lib, level=level)
        assert len(cases) == budget_for_level(level)
        ids = [c.attack_id for c in cases]
        assert len(ids) == len(set(ids))  # unique
        # Every category represented.
        assert {c.category for c in cases} == set(Category.ALL)
        # No unresolved placeholders remain.
        for c in cases:
            assert "{action}" not in c.payload
            assert "{recipient}" not in c.payload


def test_generation_is_deterministic():
    lib = AttackLibrary.load()
    a = [c.payload for c in generate(lib, level="basic")]
    b = [c.payload for c in generate(lib, level="basic")]
    assert a == b
