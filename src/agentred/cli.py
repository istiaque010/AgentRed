"""Command-line interface for AgentRed.

    agentred scan --config examples/email_agent.yaml --level standard
    agentred attacks --list
    agentred version
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .attacks import AttackLibrary
from .attack_generator import budget_for_level, generate
from .config import load_config
from .executor import Executor
from .langgraph_agent import LangGraphUnavailable
from .llm import OllamaError, build_backend
from .models import Category
from .report import ReportMeta, write_reports
from .scoring import score


def _assessment_id() -> str:
    return "AR-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _progress(i: int, total: int, result) -> None:
    if i == total or i % max(1, total // 20) == 0:
        pct = int(100 * i / total)
        bar = "#" * (pct // 5)
        sys.stdout.write(f"\r  [{bar:<20}] {i}/{total} attacks")
        sys.stdout.flush()
        if i == total:
            sys.stdout.write("\n")


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    # --model overrides the config's model for this run.
    if args.model:
        config.model = args.model

    # Resolve the attack budget: --budget flag > config levels: > defaults.
    effective_budget = args.budget or budget_for_level(args.level, config.levels)
    if args.budget:
        budget_src = "--budget override"
    elif args.level in config.levels:
        budget_src = "from config levels:"
    else:
        budget_src = "default"

    print(f"AgentRed {__version__} - security assessment")
    print(f"  Target agent : {config.name}")
    print(f"  Model        : {config.model}")
    print(f"  Backend      : {args.backend}")
    print(f"  Level        : {args.level} (budget {effective_budget}, {budget_src})")

    # Backend / agent runner.
    backend = None
    agent_builder = None
    framework = "LangGraph-compatible (built-in runner)"
    if args.backend == "langgraph":
        from .langgraph_agent import LangGraphTargetAgent

        framework = "LangGraph (ReAct) + Ollama"

        def agent_builder(env):
            return LangGraphTargetAgent(
                config, env, model=config.model, host=args.host
            )
    else:
        try:
            backend = build_backend(args.backend, config, seed=args.seed, host=args.host)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    # Attacks.
    library = AttackLibrary.load(args.attacks_dir)
    attacks = generate(library, level=args.level, budget=effective_budget)
    print(f"  Attacks      : {len(attacks)} generated from {len(library)} templates\n")

    # Execute.
    assessment_id = _assessment_id()
    executor = Executor(
        config=config,
        backend=backend,
        agent_builder=agent_builder,
        assessment_id=assessment_id,
    )
    try:
        results = executor.run_all(attacks, progress=_progress)
    except (OllamaError, LangGraphUnavailable) as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return 3

    # Score.
    assessment = score(results)
    print()
    print(f"  Attack Success Rate : {assessment.asr * 100:.1f}%")
    print(f"  Security Score      : {assessment.security_score}/100")
    print(f"  Overall Risk        : {assessment.risk}")

    # Report.
    meta = ReportMeta(
        agent_name=config.name,
        model=config.model,
        framework=framework,
        level=args.level,
        backend=args.backend,
        assessment_id=assessment_id,
    )
    paths = write_reports(meta, assessment, results, args.out)
    print("\n  Reports written:")
    for kind, path in paths.items():
        print(f"    {kind:<9}: {path}")

    return 0


def cmd_attacks(args: argparse.Namespace) -> int:
    library = AttackLibrary.load(args.attacks_dir)
    print(f"Loaded {len(library)} attack templates:\n")
    for cat in Category.ALL:
        templates = library.by_category(cat)
        print(f"  {Category.label(cat)} ({len(templates)}):")
        for t in templates:
            print(f"    - {t.template_id}: {t.description}")
        print()

    # Show budgets; if a config is given, reflect its 'levels:' overrides.
    overrides = load_config(args.config).levels if args.config else {}
    label = "scan budgets (from config)" if overrides else "scan budgets (default)"
    print(f"  {label}:")
    for level in ("basic", "standard", "deep"):
        tuned = " (tuned)" if level in overrides else ""
        print(f"    {level:<9}: {budget_for_level(level, overrides)} attacks{tuned}")
    if not overrides:
        print("\n  Tune per-level budgets by adding a 'levels:' block to your "
              "agent YAML (see README / examples/email_agent.yaml).")
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"AgentRed {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentred",
        description="Red-teaming framework for security assessment of AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"AgentRed {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Run a security assessment against an agent.")
    p_scan.add_argument("--config", required=True, help="Path to agent YAML config.")
    p_scan.add_argument(
        "--level", default="basic", choices=["basic", "standard", "deep"],
        help="Assessment intensity (attack budget).",
    )
    p_scan.add_argument(
        "--backend", default="mock", choices=["mock", "ollama", "langgraph"],
        help="Target-agent runner. 'mock' runs offline; 'ollama' uses a local "
             "model via the built-in runner; 'langgraph' runs a LangGraph ReAct "
             "agent over Ollama.",
    )
    p_scan.add_argument("--out", default="out", help="Output directory for reports.")
    p_scan.add_argument(
        "--budget", type=int, default=None,
        help="Override the attack budget for this run (wins over the level's "
             "default and any config 'levels:' value).",
    )
    p_scan.add_argument(
        "--model", default=None,
        help="Override the target model for this run (any model pulled in "
             "Ollama, e.g. llama3.1:8b). Overrides the config's 'model:'. "
             "Used by the ollama/langgraph backends.",
    )
    p_scan.add_argument("--seed", type=int, default=0, help="Seed for reproducible mock runs.")
    p_scan.add_argument("--host", default="http://localhost:11434", help="Ollama host URL.")
    p_scan.add_argument("--attacks-dir", default=None, help="Custom attack templates directory.")
    p_scan.set_defaults(func=cmd_scan)

    # attacks
    p_att = sub.add_parser("attacks", help="Inspect the attack library.")
    p_att.add_argument("--list", action="store_true", help="List attack templates.")
    p_att.add_argument("--config", default=None,
                       help="Optional agent YAML; shows its tuned per-level budgets.")
    p_att.add_argument("--attacks-dir", default=None, help="Custom attack templates directory.")
    p_att.set_defaults(func=cmd_attacks)

    # version
    p_ver = sub.add_parser("version", help="Print version.")
    p_ver.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
