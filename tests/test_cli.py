"""CLI-level tests (offline mock backend)."""

from pathlib import Path

from agentred.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = str(REPO_ROOT / "examples" / "email_agent.yaml")


def test_scan_runs_and_writes_reports(tmp_path):
    rc = main([
        "scan", "--config", EXAMPLE_CONFIG, "--backend", "mock",
        "--budget", "20", "--out", str(tmp_path),
    ])
    assert rc == 0
    assert (tmp_path / "report.html").exists()


def test_model_override_flows_into_report(tmp_path):
    rc = main([
        "scan", "--config", EXAMPLE_CONFIG, "--backend", "mock",
        "--model", "llama3.1:8b", "--budget", "12", "--out", str(tmp_path),
    ])
    assert rc == 0
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    # The overridden model is reflected in the report, not the config default.
    assert "llama3.1:8b" in html
    assert "llama3.1:8b" in md
    assert "qwen2.5:7b" not in md
