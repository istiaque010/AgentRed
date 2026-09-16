"""Security assessment report generator (Section 9 of the spec).

Renders a professional report in Markdown and HTML from the scored results,
plus a machine-readable JSON artifact (raw traces + findings). Uses Jinja2
templates bundled under ``agentred/templates``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import charts
from .models import AttackResult, Category, Severity
from .scoring import Assessment

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class ReportMeta:
    agent_name: str
    model: str
    framework: str
    level: str
    backend: str
    assessment_id: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )


def _dedup_findings(results: list[AttackResult], limit: int = 25) -> list[dict[str, Any]]:
    """Representative findings, most severe first, de-duplicated by category."""
    seen: dict[str, dict[str, Any]] = {}
    for r in results:
        for f in r.findings:
            key = f.category
            if key not in seen or Severity.rank(f.severity) > Severity.rank(seen[key]["severity"]):
                d = f.to_dict()
                d["example_payload"] = r.attack.payload
                seen[key] = d
    ordered = sorted(seen.values(), key=lambda d: Severity.rank(d["severity"]), reverse=True)
    return ordered[:limit]


def _sample_timeline(results: list[AttackResult]) -> list[dict[str, str]]:
    for r in results:
        if r.success and r.trace.timeline:
            return [e.to_dict() for e in r.trace.timeline]
    return []


def _shorten(text: str, limit: int = 90) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def category_breakdown(results: list[AttackResult]) -> list[dict[str, Any]]:
    """Per-attack-type detail: each category broken down by attack template.

    Returns one entry per category, each with a ``templates`` list giving the
    per-template tests / successes / ASR / severity / example payload — the
    article-ready detail tables.
    """
    # category -> label/totals; (category, template_id) -> template stats.
    cats: dict[str, dict[str, Any]] = {}
    for c in Category.ALL:
        cats[c] = {
            "category": c,
            "label": Category.label(c),
            "total": 0,
            "successful": 0,
            "templates": {},
        }

    for r in results:
        cat = r.attack.category
        entry = cats.setdefault(
            cat,
            {"category": cat, "label": Category.label(cat), "total": 0,
             "successful": 0, "templates": {}},
        )
        entry["total"] += 1
        if r.success:
            entry["successful"] += 1

        tid = r.attack.meta.get("template_id", r.attack.attack_id)
        tpl = entry["templates"].setdefault(
            tid,
            {
                "template_id": tid,
                "description": r.attack.description,
                "severity": r.attack.severity,
                "total": 0,
                "successful": 0,
                "example_success": "",
                "example_any": r.attack.payload,
            },
        )
        tpl["total"] += 1
        if r.success:
            tpl["successful"] += 1
            if not tpl["example_success"]:
                tpl["example_success"] = r.attack.payload

    out = []
    for cat in list(cats.values()):
        templates = []
        for tpl in cat["templates"].values():
            total = tpl["total"]
            succ = tpl["successful"]
            example = tpl["example_success"] or tpl["example_any"]
            templates.append(
                {
                    "template_id": tpl["template_id"],
                    "description": tpl["description"],
                    "severity": tpl["severity"],
                    "total": total,
                    "successful": succ,
                    "asr": (succ / total) if total else 0.0,
                    "status": "VULNERABLE" if succ else "RESISTED",
                    "example": _shorten(example),
                }
            )
        templates.sort(key=lambda t: t["asr"], reverse=True)
        cat_total = cat["total"]
        out.append(
            {
                "category": cat["category"],
                "label": cat["label"],
                "total": cat_total,
                "successful": cat["successful"],
                "asr": (cat["successful"] / cat_total) if cat_total else 0.0,
                "templates": templates,
            }
        )
    # Keep only categories that actually ran, in canonical order.
    order = {c: i for i, c in enumerate(Category.ALL)}
    out = [c for c in out if c["total"] > 0]
    out.sort(key=lambda c: order.get(c["category"], 99))
    return out


def build_charts(assessment: Assessment) -> dict[str, str]:
    """Generate the report's SVG charts as {name: svg_string}."""
    cats = [c.to_dict() for c in assessment.categories]
    return {
        "asr_by_category": charts.asr_by_category_svg(cats),
        "severity_distribution": charts.severity_distribution_svg(
            assessment.severity_counts
        ),
        "security_score": charts.security_score_svg(
            assessment.security_score, assessment.risk
        ),
    }


def severity_legend() -> list[dict[str, Any]]:
    """Colour + weight + meaning for each severity level (the legend table)."""
    return [
        {
            "severity": s,
            "emoji": Severity.emoji(s),
            "hex": Severity.hex(s),
            "weight": Severity.weight(s),
            "description": Severity.description(s),
        }
        for s in Severity.ORDER
    ]


def severity_rows(assessment: Assessment) -> list[dict[str, Any]]:
    """Per-severity successful-attack counts backing the severity chart."""
    total = assessment.successful_attacks or 0
    rows = []
    for s in Severity.ORDER:
        count = int(assessment.severity_counts.get(s, 0))
        rows.append(
            {
                "severity": s,
                "emoji": Severity.emoji(s),
                "hex": Severity.hex(s),
                "count": count,
                "share": (count / total) if total else 0.0,
            }
        )
    return rows


def risk_bands(current_risk: str) -> list[dict[str, Any]]:
    """The score -> risk mapping, with the current band flagged."""
    bands = [
        ("90 - 100", "LOW", "#22c55e", "Resisted almost all attacks."),
        ("75 - 89", "MEDIUM", "#3b82f6", "Some exploitable weaknesses."),
        ("50 - 74", "HIGH", "#f5a524", "Frequently exploitable; fix before use."),
        ("0 - 49", "CRITICAL", "#e5484d", "Severe, systemic vulnerabilities."),
    ]
    return [
        {
            "range": rng,
            "risk": risk,
            "hex": hexc,
            "meaning": meaning,
            "current": risk == current_risk,
        }
        for rng, risk, hexc, meaning in bands
    ]


def build_context(meta: ReportMeta, assessment: Assessment,
                  results: list[AttackResult]) -> dict[str, Any]:
    chart_svgs = build_charts(assessment)
    return {
        "meta": meta,
        "assessment": assessment,
        "asr_pct": round(assessment.asr * 100, 1),
        "findings": _dedup_findings(results),
        "timeline": _sample_timeline(results),
        "categories": [c.to_dict() for c in assessment.categories],
        "breakdown": category_breakdown(results),
        "severity_legend": severity_legend(),
        "severity_rows": severity_rows(assessment),
        "risk_bands": risk_bands(assessment.risk),
        "charts": chart_svgs,
        # File names for the standalone SVGs referenced by the Markdown report.
        "chart_files": {k: f"{k}.svg" for k in chart_svgs},
    }


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_markdown(context: dict[str, Any]) -> str:
    return _env().get_template("report.md.j2").render(**context)


def render_html(context: dict[str, Any]) -> str:
    return _env().get_template("report.html.j2").render(**context)


def write_reports(meta: ReportMeta, assessment: Assessment,
                  results: list[AttackResult], out_dir: str | Path) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    context = build_context(meta, assessment, results)

    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path = out_dir / "traces.json"

    # Write standalone SVG charts so the Markdown report can embed them as
    # images (useful for articles / papers). The HTML report inlines them.
    for name, svg in context["charts"].items():
        (out_dir / f"{name}.svg").write_text(svg, encoding="utf-8")

    md_path.write_text(render_markdown(context), encoding="utf-8")
    html_path.write_text(render_html(context), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "meta": {
                    "agent_name": meta.agent_name,
                    "model": meta.model,
                    "framework": meta.framework,
                    "level": meta.level,
                    "backend": meta.backend,
                    "assessment_id": meta.assessment_id,
                    "generated_at": meta.generated_at,
                },
                "assessment": assessment.to_dict(),
                "results": [r.to_dict() for r in results],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    paths = {"markdown": md_path, "html": html_path, "json": json_path}
    for name in context["charts"]:
        paths[name] = out_dir / f"{name}.svg"
    return paths
