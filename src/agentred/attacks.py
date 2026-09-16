"""Attack library and loader (Sections 1.1 / 4 of the spec).

Attack *templates* live in the top-level ``attacks/`` directory as YAML files,
one per category. Each template can contain ``{action}`` and ``{recipient}``
placeholders that the generator expands into concrete attack cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Category, Severity

# Default location of the bundled attack templates. They ship inside the
# package (src/agentred/data/attacks) so they are available after `pip install`.
DEFAULT_ATTACKS_DIR = Path(__file__).resolve().parent / "data" / "attacks"

_CATEGORY_FILES = {
    Category.PROMPT_INJECTION: "prompt_injection.yaml",
    Category.TOOL_MISUSE: "tool_misuse.yaml",
    Category.DATA_LEAKAGE: "data_leakage.yaml",
    Category.PROMPT_LEAKAGE: "prompt_leakage.yaml",
}


@dataclass
class AttackTemplate:
    """A parameterised attack from which many concrete cases are generated."""

    template_id: str
    category: str
    description: str
    payload: str
    target_behavior: str
    success_condition: str
    severity: str = Severity.HIGH
    channel: str = "email"
    actions: list[str] = field(default_factory=list)
    recipients: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


class AttackLibrary:
    """Loads and holds attack templates grouped by category."""

    def __init__(self, templates: list[AttackTemplate]):
        self.templates = templates

    def by_category(self, category: str) -> list[AttackTemplate]:
        return [t for t in self.templates if t.category == category]

    def categories(self) -> list[str]:
        return sorted({t.category for t in self.templates})

    def __len__(self) -> int:
        return len(self.templates)

    @classmethod
    def load(cls, directory: str | Path | None = None) -> "AttackLibrary":
        directory = Path(directory) if directory else DEFAULT_ATTACKS_DIR
        templates: list[AttackTemplate] = []
        for category, filename in _CATEGORY_FILES.items():
            path = directory / filename
            if not path.exists():
                continue
            templates.extend(_load_file(path, category))
        if not templates:
            raise FileNotFoundError(
                f"No attack templates found in {directory}. Expected files like "
                f"prompt_injection.yaml."
            )
        return cls(templates)


def _load_file(path: Path, category: str) -> list[AttackTemplate]:
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    defaults = raw.get("defaults", {}) or {}
    entries = raw.get("attacks", []) or []
    out: list[AttackTemplate] = []
    for i, entry in enumerate(entries):
        merged = {**defaults, **entry}
        out.append(
            AttackTemplate(
                template_id=merged.get("id", f"{category[:2].upper()}{i:03d}"),
                category=merged.get("category", category),
                description=merged.get("description", ""),
                payload=merged.get("payload", ""),
                target_behavior=merged.get("target_behavior", ""),
                success_condition=merged.get("success_condition", ""),
                severity=str(merged.get("severity", Severity.HIGH)).upper(),
                channel=merged.get("channel", "email"),
                actions=list(merged.get("actions", [])),
                recipients=list(merged.get("recipients", [])),
                meta=merged.get("meta", {}) or {},
            )
        )
    return out
