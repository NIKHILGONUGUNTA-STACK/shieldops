"""Command line interface for the Aegis Shift-Left API Security Gate."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import typer

from simulation.ci_gate.models import (
    GateReport,
    GateVerdict,
)
from simulation.ci_gate.parser import SpecParser
from simulation.ci_gate.reconciler import SpecReconciler
from simulation.ci_gate.reporter import GateReporter

app = typer.Typer(
    name="aegis-ci-gate",
    help="ShieldOps Shift-Left API Security Gate CLI for CI/CD pipelines.",
    add_completion=False,
)


@app.command(name="scan")
def scan_cmd(
    spec_path: str = typer.Argument(..., help="Path to target OpenAPI 3.0/3.1 YAML or JSON spec file."),
    base_spec: Optional[str] = typer.Option(None, "--base-spec", "-b", help="Path to base/production OpenAPI spec for regression diffing."),
    gateway_url: Optional[str] = typer.Option(None, "--gateway-url", "-g", help="Base URL of live ShieldOps Gateway for wire telemetry reconciliation."),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Bearer JWT or API token for Gateway authentication."),
    posture_threshold: float = typer.Option(75.0, "--threshold", help="Minimum required API security posture score percent (default 75.0%)."),
    fail_on_breaking: bool = typer.Option(True, "--fail-on-breaking/--no-fail-on-breaking", help="Fail build with non-zero exit code on breaking changes."),
    output_format: str = typer.Option("terminal", "--format", "-f", help="Output format: 'terminal', 'markdown', or 'json'."),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-o", help="Optional file destination to write rendered output."),
) -> None:
    """Scans an OpenAPI specification against Shift-Left security policies and contract regressions."""
    try:
        candidate_parser = SpecParser(spec_path)
    except Exception as e:
        typer.secho(f"Error reading specification: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    summary, findings = candidate_parser.analyze(posture_threshold=posture_threshold)
    contract_diffs = []

    # 1. Base spec comparison if provided
    if base_spec:
        try:
            base_parser = SpecParser(base_spec)
            diffs, breaking_findings = SpecReconciler.compare_specs(base_parser, candidate_parser)
            contract_diffs.extend(diffs)
            findings.extend(breaking_findings)
        except Exception as e:
            typer.secho(f"Warning: Failed to load base spec for diffing: {e}", fg=typer.colors.YELLOW)

    # 2. Gateway reconciliation if URL provided
    gateway_connected = False
    if gateway_url:
        shadow_findings = SpecReconciler.reconcile_with_gateway(gateway_url, candidate_parser, token=token)
        if shadow_findings:
            gateway_connected = True
            findings.extend(shadow_findings)

    # Recalculate summary metrics after reconciliation additions
    critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.value == "HIGH")
    medium_count = sum(1 for f in findings if f.severity.value == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity.value == "LOW")
    breaking_count = sum(1 for f in findings if f.breaking)

    penalty = (critical_count * 25.0) + (high_count * 15.0) + (medium_count * 5.0) + (low_count * 1.0)
    posture_score = max(0.0, 100.0 - penalty)

    verdict = GateVerdict.PASSED
    if breaking_count > 0 or posture_score < posture_threshold:
        verdict = GateVerdict.FAILED
    elif high_count > 0 or medium_count > 0:
        verdict = GateVerdict.WARNING

    summary.critical_count = critical_count
    summary.high_count = high_count
    summary.medium_count = medium_count
    summary.low_count = low_count
    summary.breaking_count = breaking_count
    summary.posture_score = round(posture_score, 1)
    summary.verdict = verdict

    report = GateReport(
        spec_path=str(Path(spec_path).resolve()),
        spec_title=candidate_parser.title,
        spec_version=candidate_parser.version,
        gateway_connected=gateway_connected,
        gateway_url=gateway_url,
        summary=summary,
        findings=findings,
        contract_diffs=contract_diffs,
        evaluated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
    )

    # Render output format
    fmt = output_format.lower().strip()
    if fmt == "json":
        output_str = GateReporter.render_json(report)
    elif fmt == "markdown":
        output_str = GateReporter.render_markdown(report)
    else:
        output_str = GateReporter.render_terminal(report)

    # Write to file if requested
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")

    # Output to stdout
    typer.echo(output_str)

    # Determine exit code
    if fail_on_breaking and verdict == GateVerdict.FAILED:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="diff")
def diff_cmd(
    base_spec: str = typer.Argument(..., help="Path to base OpenAPI specification."),
    target_spec: str = typer.Argument(..., help="Path to modified target OpenAPI specification."),
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: 'markdown', 'terminal', or 'json'."),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-o", help="Optional output file path."),
) -> None:
    """Computes contract structural differences and breaking changes between two OpenAPI specifications."""
    try:
        base = SpecParser(base_spec)
        target = SpecParser(target_spec)
    except Exception as e:
        typer.secho(f"Error loading specification: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    diffs, breaking_findings = SpecReconciler.compare_specs(base, target)
    target_summary, target_findings = target.analyze()
    all_findings = target_findings + breaking_findings

    breaking_count = sum(1 for f in all_findings if f.breaking)
    verdict = GateVerdict.FAILED if breaking_count > 0 else GateVerdict.PASSED

    target_summary.breaking_count = breaking_count
    target_summary.verdict = verdict

    report = GateReport(
        spec_path=str(Path(target_spec).resolve()),
        spec_title=target.title,
        spec_version=target.version,
        gateway_connected=False,
        summary=target_summary,
        findings=all_findings,
        contract_diffs=diffs,
        evaluated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
    )

    fmt = output_format.lower().strip()
    if fmt == "json":
        output_str = GateReporter.render_json(report)
    elif fmt == "terminal":
        output_str = GateReporter.render_terminal(report)
    else:
        output_str = GateReporter.render_markdown(report)

    if output_file:
        Path(output_file).write_text(output_str, encoding="utf-8")

    typer.echo(output_str)
    if breaking_count > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="version")
def version_cmd() -> None:
    """Displays the Aegis Shift-Left CI Gate version and environment."""
    typer.echo("Aegis ShieldOps API Security CI Gate v1.0.0 (Phase 7.8)")


if __name__ == "__main__":
    app()
