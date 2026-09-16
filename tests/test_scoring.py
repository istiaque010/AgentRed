"""Scoring engine tests."""

from agentred.models import (
    AttackCase,
    AttackResult,
    Category,
    ExecutionTrace,
    Finding,
    Severity,
)
from agentred.scoring import score


def _result(category, severity, success):
    attack = AttackCase(
        attack_id="X",
        category=category,
        description="",
        payload="",
        target_behavior="",
        success_condition="",
        severity=severity,
    )
    trace = ExecutionTrace(assessment_id="A", attack_id="X", category=category)
    findings = []
    if success:
        findings = [Finding(
            finding_id="F", attack_id="X", severity=severity, category=category,
            status="VULNERABLE", description="", evidence="", impact="",
            recommendation="",
        )]
    return AttackResult(attack=attack, trace=trace, findings=findings, success=success)


def test_perfect_score_when_no_success():
    results = [_result(Category.PROMPT_INJECTION, Severity.HIGH, False) for _ in range(10)]
    a = score(results)
    assert a.security_score == 100
    assert a.risk == "LOW"
    assert a.asr == 0.0


def test_asr_and_penalty():
    results = (
        [_result(Category.DATA_LEAKAGE, Severity.CRITICAL, True) for _ in range(5)]
        + [_result(Category.DATA_LEAKAGE, Severity.CRITICAL, False) for _ in range(5)]
    )
    a = score(results)
    assert a.total_attacks == 10
    assert a.successful_attacks == 5
    assert abs(a.asr - 0.5) < 1e-9
    # Half of equally-weighted attacks succeeded -> score around 50.
    assert 45 <= a.security_score <= 55
    assert a.risk in ("HIGH", "CRITICAL")


def test_category_breakdown():
    results = [
        _result(Category.PROMPT_INJECTION, Severity.HIGH, True),
        _result(Category.TOOL_MISUSE, Severity.HIGH, False),
    ]
    a = score(results)
    by_cat = {c.category: c for c in a.categories}
    assert by_cat[Category.PROMPT_INJECTION].successful == 1
    assert by_cat[Category.TOOL_MISUSE].successful == 0
