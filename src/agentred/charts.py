"""Dependency-free SVG chart generation for reports.

Produces self-contained SVG strings (no external libraries) so the reports stay
offline-friendly. Charts render as "figure cards" with a white background and
dark text, so they look right both inline in the dark HTML report and when
embedded standalone into an article, paper, or slide deck.

Charts provided:

* :func:`asr_by_category_svg`   - horizontal bars of Attack Success Rate.
* :func:`severity_distribution_svg` - successful attacks by finding severity.
* :func:`security_score_svg`    - a 0-100 score bar with the risk band.
"""

from __future__ import annotations

from html import escape
from typing import Any

# Palette (shared with the HTML report).
CATEGORY_COLORS = {
    "indirect_prompt_injection": "#6366f1",
    "tool_misuse": "#f5a524",
    "sensitive_data_leakage": "#e5484d",
    "system_prompt_leakage": "#14b8a6",
}
SEVERITY_COLORS = {
    "CRITICAL": "#e5484d",
    "HIGH": "#f5a524",
    "MEDIUM": "#3b82f6",
    "LOW": "#22c55e",
}
RISK_COLORS = {
    "LOW": "#22c55e",
    "MEDIUM": "#3b82f6",
    "HIGH": "#f5a524",
    "CRITICAL": "#e5484d",
}

_INK = "#1a1d24"
_MUTED = "#5b6472"
_CARD = "#ffffff"
_GRID = "#e6e8ee"
_TRACK = "#eef0f4"
_FONT = "font-family='-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif'"


def _frame(width: int, height: int, title: str, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" '
        f'aria-label="{escape(title)}">'
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" '
        f'fill="{_CARD}" stroke="{_GRID}"/>'
        f'<text x="20" y="30" {_FONT} font-size="15" font-weight="700" '
        f'fill="{_INK}">{escape(title)}</text>'
        f"{body}</svg>"
    )


def asr_by_category_svg(categories: list[dict[str, Any]]) -> str:
    """Horizontal ASR bars, one row per category."""
    rows = [c for c in categories if c.get("total", 0) > 0]
    width, top, row_h, gap = 640, 52, 30, 14
    left, label_w = 20, 150
    bar_x = left + label_w
    bar_max = width - bar_x - 70
    height = top + len(rows) * (row_h + gap) + 10

    body = []
    y = top
    for c in rows:
        asr = c.get("asr", 0.0)
        color = CATEGORY_COLORS.get(c["category"], "#6366f1")
        bar_w = max(2, int(bar_max * asr))
        pct = f"{asr * 100:.1f}%"
        counts = f"{c['successful']}/{c['total']}"
        body.append(
            f'<text x="{left}" y="{y + row_h / 2 + 4}" {_FONT} font-size="12" '
            f'fill="{_INK}">{escape(c["label"])}</text>'
            f'<rect x="{bar_x}" y="{y}" width="{bar_max}" height="{row_h}" rx="5" '
            f'fill="{_TRACK}"/>'
            f'<rect x="{bar_x}" y="{y}" width="{bar_w}" height="{row_h}" rx="5" '
            f'fill="{color}"/>'
            f'<text x="{bar_x + bar_max + 8}" y="{y + row_h / 2 + 4}" {_FONT} '
            f'font-size="12" font-weight="700" fill="{_INK}">{pct}</text>'
            f'<text x="{bar_x + 8}" y="{y + row_h / 2 + 4}" {_FONT} font-size="11" '
            f'fill="#ffffff">{counts}</text>'
        )
        y += row_h + gap
    return _frame(width, height, "Attack Success Rate by Category", "".join(body))


def severity_distribution_svg(severity_counts: dict[str, int]) -> str:
    """Vertical bars of successful attacks grouped by finding severity.

    Bars are colour-coded by severity; the colour key lives in the report's
    severity tables (sections 2.2 / 2.3), so no in-figure legend is repeated.
    """
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    data = [(s, int(severity_counts.get(s, 0))) for s in order]
    width, height = 640, 240
    base_y, top_y = 200, 60
    left = 60
    slot = (width - left - 30) / len(data)
    bar_w = slot * 0.5
    peak = max((v for _, v in data), default=0) or 1

    body = [
        f'<line x1="{left}" y1="{base_y}" x2="{width - 20}" y2="{base_y}" '
        f'stroke="{_GRID}"/>'
    ]
    for i, (sev, val) in enumerate(data):
        cx = left + slot * i + (slot - bar_w) / 2
        h = int((base_y - top_y) * (val / peak))
        y = base_y - h
        color = SEVERITY_COLORS[sev]
        body.append(
            f'<rect x="{cx:.1f}" y="{y}" width="{bar_w:.1f}" height="{h}" rx="4" '
            f'fill="{color}"/>'
            f'<text x="{cx + bar_w / 2:.1f}" y="{y - 8}" {_FONT} font-size="13" '
            f'font-weight="700" fill="{_INK}" text-anchor="middle">{val}</text>'
            f'<text x="{cx + bar_w / 2:.1f}" y="{base_y + 20}" {_FONT} '
            f'font-size="11" fill="{_MUTED}" text-anchor="middle">{sev}</text>'
        )
    return _frame(width, height, "Successful Attacks by Severity", "".join(body))


def security_score_svg(score: int, risk: str) -> str:
    """A 0-100 score bar with a marker and the risk band."""
    width, height = 640, 130
    left, right = 20, 20
    track_x = left
    track_w = width - left - right
    track_y = 70
    track_h = 22
    color = RISK_COLORS.get(risk, "#3b82f6")
    fill_w = max(2, int(track_w * (score / 100)))

    body = (
        f'<text x="{width - 20}" y="30" {_FONT} font-size="13" '
        f'fill="{_MUTED}" text-anchor="end">Risk: '
        f'<tspan font-weight="700" fill="{color}">{escape(risk)}</tspan></text>'
        f'<text x="20" y="58" {_FONT} font-size="26" font-weight="800" '
        f'fill="{_INK}">{score}<tspan font-size="14" font-weight="600" '
        f'fill="{_MUTED}">/100</tspan></text>'
        f'<rect x="{track_x}" y="{track_y}" width="{track_w}" height="{track_h}" '
        f'rx="11" fill="{_TRACK}"/>'
        f'<rect x="{track_x}" y="{track_y}" width="{fill_w}" height="{track_h}" '
        f'rx="11" fill="{color}"/>'
    )
    # 0 / 50 / 100 ticks.
    for frac, lbl in ((0.0, "0"), (0.5, "50"), (1.0, "100")):
        x = track_x + track_w * frac
        anchor = "start" if frac == 0 else "end" if frac == 1 else "middle"
        body += (
            f'<text x="{x:.0f}" y="{track_y + track_h + 18}" {_FONT} '
            f'font-size="11" fill="{_MUTED}" text-anchor="{anchor}">{lbl}</text>'
        )
    return _frame(width, height, "Overall Security Score", body)
