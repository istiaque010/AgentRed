"""End-to-end scan: generation -> execution -> detection -> scoring -> report."""

from agentred.attacks import AttackLibrary
from agentred.attack_generator import budget_for_level, generate
from agentred.executor import Executor
from agentred.llm import MockBackend
from agentred.models import Category
from agentred.report import ReportMeta, write_reports
from agentred.scoring import score


def _run(config, level="basic", seed=0):
    backend = MockBackend(config, seed=seed)
    attacks = generate(AttackLibrary.load(), level=level)
    executor = Executor(config=config, backend=backend, assessment_id="AR-TEST")
    results = executor.run_all(attacks)
    return results


def test_full_scan_produces_findings(config):
    results = _run(config)
    assert len(results) == budget_for_level("basic")
    # A vulnerable mock should produce at least some successes across categories.
    successes = [r for r in results if r.success]
    assert successes, "expected the mock agent to be exploited at least once"
    categories_hit = {r.attack.category for r in successes}
    assert categories_hit  # at least one category compromised
    # Every successful result carries at least one finding.
    assert all(r.findings for r in successes)


def test_scan_is_reproducible(config):
    a = _run(config, seed=7)
    b = _run(config, seed=7)
    assert [r.success for r in a] == [r.success for r in b]


def test_scoring_and_report_written(config, tmp_path):
    results = _run(config)
    assessment = score(results)
    assert 0 <= assessment.security_score <= 100
    assert assessment.risk in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    meta = ReportMeta(
        agent_name=config.name, model=config.model, framework="test",
        level="basic", backend="mock", assessment_id="AR-TEST",
    )
    paths = write_reports(meta, assessment, results, tmp_path)
    assert paths["markdown"].exists()
    assert paths["html"].exists()
    assert paths["json"].exists()
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "# AgentRed" in md
    assert "Red-Teaming Framework for Security Assessment of AI Agents" in md
    html = paths["html"].read_text(encoding="utf-8")
    assert "<html" in html.lower()
    assert "Red-Teaming Framework for Security Assessment of AI Agents" in html


def test_data_leak_attacks_can_leak_canary(config):
    """At least one data-leakage attack should surface the canary secret."""
    results = _run(config, level="standard")
    leaked = any(
        config.canary in f.evidence
        for r in results
        for f in r.findings
        if f.category == Category.DATA_LEAKAGE
    )
    assert leaked
