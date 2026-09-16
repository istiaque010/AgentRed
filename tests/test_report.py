"""Report breakdown, charts, and article-ready output."""

from agentred import charts
from agentred.attacks import AttackLibrary
from agentred.attack_generator import generate
from agentred.executor import Executor
from agentred.llm import MockBackend
from agentred.models import Category
from agentred.report import (
    ReportMeta,
    build_charts,
    category_breakdown,
    risk_bands,
    severity_legend,
    severity_rows,
    write_reports,
)
from agentred.models import Severity
from agentred.scoring import score


def _results(config, level="basic"):
    backend = MockBackend(config, seed=3)
    attacks = generate(AttackLibrary.load(), level=level)
    return Executor(config=config, backend=backend, assessment_id="AR-T").run_all(attacks)


def test_category_breakdown_structure_and_totals(config):
    results = _results(config)
    breakdown = category_breakdown(results)
    # Every category that ran is present, canonical order.
    cats = [c["category"] for c in breakdown]
    assert cats == [c for c in Category.ALL if c in cats]

    for c in breakdown:
        # Per-template tests sum to the category total.
        assert sum(t["total"] for t in c["templates"]) == c["total"]
        assert sum(t["successful"] for t in c["templates"]) == c["successful"]
        # Templates sorted by ASR descending.
        asrs = [t["asr"] for t in c["templates"]]
        assert asrs == sorted(asrs, reverse=True)
        # Each template row carries the article-ready fields.
        for t in c["templates"]:
            assert t["template_id"] and t["description"]
            assert t["status"] in ("VULNERABLE", "RESISTED")
            assert 0.0 <= t["asr"] <= 1.0


def test_charts_are_valid_svg(config):
    assessment = score(_results(config))
    svgs = build_charts(assessment)
    assert set(svgs) == {"asr_by_category", "severity_distribution", "security_score"}
    for svg in svgs.values():
        assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
        assert "xmlns" in svg


def test_chart_functions_handle_empty():
    # Should not raise on empty inputs.
    assert "<svg" in charts.asr_by_category_svg([])
    assert "<svg" in charts.severity_distribution_svg({})
    assert "<svg" in charts.security_score_svg(100, "LOW")


def test_severity_legend_has_colour_and_meaning():
    legend = severity_legend()
    assert [s["severity"] for s in legend] == Severity.ORDER
    for s in legend:
        assert s["emoji"] and s["hex"].startswith("#")
        assert s["description"]  # colour description / meaning present
        assert s["weight"] == Severity.weight(s["severity"])


def test_severity_rows_counts_and_shares(config):
    assessment = score(_results(config))
    rows = severity_rows(assessment)
    assert [r["severity"] for r in rows] == Severity.ORDER
    # Counts match the assessment's severity_counts.
    for r in rows:
        assert r["count"] == assessment.severity_counts.get(r["severity"], 0)
    # Shares sum to ~1 when there are any successful attacks.
    if assessment.successful_attacks:
        assert abs(sum(r["share"] for r in rows) - 1.0) < 1e-6


def test_risk_bands_flags_current():
    bands = risk_bands("HIGH")
    assert len(bands) == 4
    current = [b for b in bands if b["current"]]
    assert len(current) == 1 and current[0]["risk"] == "HIGH"


def test_reports_written_with_charts_and_detail_tables(config, tmp_path):
    results = _results(config)
    assessment = score(results)
    meta = ReportMeta(
        agent_name=config.name, model=config.model, framework="test",
        level="basic", backend="mock", assessment_id="AR-T",
    )
    paths = write_reports(meta, assessment, results, tmp_path)

    # SVG chart files exist and are referenced by the Markdown report.
    for name in ("asr_by_category", "severity_distribution", "security_score"):
        assert paths[name].exists()
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "Detailed Results by Attack Type" in md
    assert "asr_by_category.svg" in md  # image reference
    assert "| Attack | Description |" in md  # per-type detail table header
    # Intermediate tables present.
    assert "Severity Levels (colour key)" in md
    assert "Successful Attacks by Severity" in md
    assert "Risk Rating Scale" in md

    # HTML inlines the charts and detail tables.
    html = paths["html"].read_text(encoding="utf-8")
    assert html.count("<svg") >= 3
    assert "Detailed Results by Attack Type" in html
    assert "Severity Levels" in html
    assert "swatch" in html  # colour swatches in the legend table
    # Save-as-PDF button (print-to-PDF keeps the same style).
    assert "window.print()" in html
    assert "Save as PDF" in html
