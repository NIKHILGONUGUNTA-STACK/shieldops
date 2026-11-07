"""Aegis Simulation Command Line Interface (CLI).

Provides operational commands for configuration validation, environment health checks,
scenario listing, and framework diagnostics using Typer and Rich.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import sys
import time
from typing import Optional
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from simulation import __version__
from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig, load_config
from simulation.reporting.reporter import ScenarioReporter
from simulation.scenarios.registry import get_default_registry
from simulation.scenarios.soc_verifier import SocTelemetryVerifier
from simulation.currency import (
    calculate_inr_equivalent,
    format_dual_presentation,
    format_inr,
    DEMONSTRATION_DISCLAIMER,
)

app = typer.Typer(
    name="aegis-sim",
    help="Aegis FinTech Simulation Framework CLI.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Inspect and validate simulation configuration.")
scenarios_app = typer.Typer(help="Inspect registered simulation scenarios.")

app.add_typer(config_app, name="config")
app.add_typer(scenarios_app, name="scenarios")

console = Console()


@app.command("version")
def version_cmd() -> None:
    """Displays framework version and active phase."""
    console.print(
        f"[bold cyan]Aegis Simulation Framework[/bold cyan] "
        f"[green]v{__version__}[/green] [dim](Phase 7.2.3.1 First Benign Journey)[/dim]"
    )


async def _execute_scenario_flow(
    scenario_id: str,
    dry_run: bool,
    verify_soc: bool,
    config: SimulationConfig,
) -> tuple[Any, Any]:
    """Asynchronously runs the scenario and optional SOC verification."""
    registry = get_default_registry()
    metadata = registry.get_metadata(scenario_id)
    scenario_cls = registry.get_class(scenario_id)

    if not metadata or not scenario_cls:
        raise ValueError(f"Scenario '{scenario_id}' is not an executable scenario")

    scenario_instance = scenario_cls(metadata, config, dry_run=dry_run)

    async with GatewayClient(config.gateway) as gateway:
        async with KeycloakAuthManager(config.keycloak) as auth:
            start_time = datetime.now(timezone.utc)
            summary = await scenario_instance.run(gateway, auth)
            end_time = datetime.now(timezone.utc)

            soc_result = None
            if not dry_run and verify_soc and summary.status.value == "SUCCESS":
                correlation_ids = getattr(scenario_instance, "recorded_correlation_ids", [])
                run_id = getattr(scenario_instance, "run_id", "run-unknown")
                verifier = SocTelemetryVerifier(config, gateway, auth)
                soc_result = await verifier.verify_benign_run(
                    correlation_ids=correlation_ids,
                    start_time=start_time,
                    end_time=end_time,
                    run_id=run_id,
                )

            return summary, getattr(scenario_instance, "created_resources", {}), soc_result


@app.command("run")
def run_cmd(
    scenario: str = typer.Option(
        "SCEN-BENIGN-01",
        "--scenario",
        "-s",
        help="Identifier of the scenario to execute",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Execute safe preflight inspection without business mutations (transfers/debits)",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Explicitly permit live business data mutations against local testbed",
    ),
    verify_soc: bool = typer.Option(
        True,
        "--verify-soc/--no-verify-soc",
        help="Query Aegis SOC APIs to verify telemetry ingestion and zero false positives",
    ),
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML configuration file",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to write serialized JSON execution report",
    ),
) -> None:
    """Executes a simulation scenario against the local Aegis Gateway testbed."""
    # 1. Enforce explicit execution / dry-run safety flags
    if not dry_run and not execute:
        console.print(
            "[bold red]Safety Invariant Error:[/bold red] You must specify either [cyan]--dry-run[/cyan] "
            "(safe preflight check) or [cyan]--execute[/cyan] (permits local business mutations).\n"
            "Example: [green]python -m simulation.cli run --scenario SCEN-BENIGN-01 --dry-run[/green]"
        )
        raise typer.Exit(code=1)

    if dry_run and execute:
        console.print(
            "[bold red]Safety Error:[/bold red] Cannot specify both [cyan]--dry-run[/cyan] "
            "and [cyan]--execute[/cyan] simultaneously."
        )
        raise typer.Exit(code=1)

    # 2. Validate configuration
    try:
        config = load_config(config_path=config_file)
    except Exception as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 3. Check scenario registry
    registry = get_default_registry()
    metadata = registry.get_metadata(scenario)
    if not metadata:
        console.print(f"[bold red]Error:[/bold red] Scenario '{scenario}' is not recognized.")
        raise typer.Exit(code=1)

    if not metadata.is_implemented:
        console.print(
            f"[bold yellow]Scenario '{scenario}' ({metadata.name}) is planned for Phase 7.2.3 "
            f"and has no executable implementation yet.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    # 4. Display Preflight Plan
    mode_str = "[bold yellow][DRY RUN — NON-MUTATING PREFLIGHT][/bold yellow]" if dry_run else "[bold green][LIVE LOCAL EXECUTION][/bold green]"
    planned_transfer_str = format_dual_presentation(
        config.benign_flow.transfer_amount,
        config.benign_flow.transfer_currency,
    )

    console.print(
        Panel(
            f"[bold white]Aegis FinTech Simulation Runner[/bold white]\n"
            f"Scenario: [bold magenta]{metadata.id}[/bold magenta] — {metadata.name}\n"
            f"Mode: {mode_str}\n"
            f"Target Gateway: [cyan]{config.gateway.base_url}[/cyan]\n"
            f"Identities: [green]Alex Morgan (Source)[/green] -> [yellow]Sam Taylor (Destination)[/yellow]\n"
            f"Planned Transfer: [bold white]{planned_transfer_str}[/bold white]\n"
            f"Destination Ref: [dim]{config.benign_flow.destination_account_reference}[/dim]\n"
            f"Permitted Mutations: [dim]Beneficiary creation (if needed), Account debit, Transaction record[/dim]",
            title="Execution Manifest",
            border_style="cyan",
        )
    )

    console.print("[dim]Executing scenario journey steps through Gateway...[/dim]")
    try:
        summary, created_resources, soc_result = asyncio.run(
            _execute_scenario_flow(scenario, dry_run, verify_soc, config)
        )
    except Exception as e:
        console.print(f"[bold red]Scenario Execution Failed:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 5. Render Run Summary Table
    table = Table(title=f"Execution Results: {metadata.id}", header_style="bold cyan")
    table.add_column("Metric", style="bold white", width=26)
    table.add_column("Value", style="green")

    table.add_row("Execution Status", f"[bold green]{summary.status.value}[/bold green]" if summary.status.value == "SUCCESS" else f"[bold red]{summary.status.value}[/bold red]")
    table.add_row("Total Requests", str(summary.total_requests))
    table.add_row("Successful Requests", str(summary.successful_requests))
    table.add_row("Failed Requests", str(summary.failed_requests))
    table.add_row("Status Codes", ", ".join(f"{code}: {cnt}" for code, cnt in summary.status_distribution.items()) or "none")

    if summary.execution_errors:
        table.add_row("Execution Errors", f"[bold red]{'; '.join(summary.execution_errors)}[/bold red]")

    for k, v in created_resources.items():
        table.add_row(f"Resource ({k})", str(v))

    console.print(table)

    # 5.1 If dry-run, display Planned Mutations table
    if dry_run and summary.run_manifest and summary.run_manifest.planned_mutations:
        mut_table = Table(title="Planned Mutations (Dry-Run Preflight Only)", header_style="bold yellow")
        mut_table.add_column("Action", style="bold white", width=22)
        mut_table.add_column("Details", style="cyan")
        for mut in summary.run_manifest.planned_mutations:
            action = mut.get("action", "MUTATION")
            curr = mut.get("currency", "USD")
            formatted_parts = []
            for k, v in mut.items():
                if k == "action":
                    continue
                if k in ("amount", "preflightSourceBalance", "projectedPostBalance"):
                    equiv = calculate_inr_equivalent(v, curr)
                    if equiv:
                        formatted_parts.append(f"{k}={v} {curr} (≈ {format_inr(equiv[0])} INR)")
                    else:
                        formatted_parts.append(f"{k}={v} {curr}")
                else:
                    formatted_parts.append(f"{k}={v}")
            details = ", ".join(formatted_parts)
            mut_table.add_row(action, details)
        console.print(mut_table)
        console.print(
            "[dim]* INR values are demonstration reference equivalents calculated at fixed demonstration rates "
            "(1 USD = 84.00 INR, 1 GBP = 108.50 INR) using Indian numbering system ('en-IN'). "
            "Not actual ledger balances or executed conversions.[/dim]"
        )

    # 6. Render SOC Verification Table if executed
    if soc_result:
        soc_table = Table(title="Aegis SOC Telemetry Verification", header_style="bold magenta")
        soc_table.add_column("Assertion", style="bold white", width=34)
        soc_table.add_column("Outcome", width=16)
        soc_table.add_column("Details", style="dim")

        # Telemetry ingestion
        telemetry_ok = soc_result.events_verified == soc_result.total_expected_events and soc_result.total_expected_events > 0
        soc_table.add_row(
            "Gateway Wire Telemetry Ingested",
            "[bold green][OK] PASS[/bold green]" if telemetry_ok else "[bold red][FAIL] FAIL[/bold red]",
            f"{soc_result.events_verified}/{soc_result.total_expected_events} correlation IDs ingested",
        )

        # False positive incidents check
        incidents_ok = soc_result.new_incidents_count == 0
        soc_table.add_row(
            "Zero False Positive Incidents",
            "[bold green][OK] PASS[/bold green]" if incidents_ok else "[bold red][FAIL] FAIL[/bold red]",
            f"{soc_result.new_incidents_count} unexpected incident(s) flagged",
        )

        # Posture safety invariant and pagination
        posture_ok = soc_result.posture_confirmed_vulnerability_false and soc_result.posture_verified
        soc_table.add_row(
            "Posture Invariant (confirmedVuln=false)",
            "[bold green][OK] PASS[/bold green]" if posture_ok else "[bold red][FAIL] FAIL[/bold red]",
            f"{soc_result.endpoints_inspected_count} endpoints inspected across all pages",
        )

        # Overall Categorical Outcome
        outcome_color = {
            "PASS": "bold green",
            "FAIL": "bold red",
            "INCOMPLETE": "bold yellow",
            "UNAVAILABLE": "bold cyan",
        }.get(soc_result.outcome.value, "white")
        soc_table.add_row(
            "Overall Verification Outcome",
            f"[{outcome_color}][{soc_result.outcome.value}][/{outcome_color}]",
            ", ".join(soc_result.diagnostics) if soc_result.diagnostics else "All SOC assertions verified",
        )

        console.print(soc_table)

    # 7. Write Trace Manifest and Run Report
    reporter = ScenarioReporter(environment_id=config.execution.environment_id)
    reporter.record_scenario(summary)
    
    # Save manifest
    if summary.run_manifest:
        ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        target_path = output_file or f"simulation/reports/run-{ts_slug}-{metadata.id.lower()}.json"
        saved_file = ScenarioReporter.save_manifest(summary.run_manifest, target_path)
        console.print(f"[dim]Run trace manifest saved to {saved_file}[/dim]")

    if summary.status.value != "SUCCESS":
        raise typer.Exit(code=1)


@config_app.command("validate")
def config_validate_cmd(
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML configuration file",
    ),
) -> None:
    """Validates configuration files, environment variables, and local-only safeguards."""
    try:
        config = load_config(config_path=config_file)
    except Exception as e:
        console.print(f"[bold red]Configuration Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    table = Table(title="Aegis Simulation Configuration", header_style="bold magenta")
    table.add_column("Component", style="cyan", width=22)
    table.add_column("Property", style="white", width=26)
    table.add_column("Configured Value", style="green")

    table.add_row("Gateway", "Base URL", config.gateway.base_url)
    table.add_row("Gateway", "Timeout (seconds)", str(config.gateway.timeout_seconds))
    table.add_row("Gateway", "Max Retries", str(config.gateway.max_retries))
    table.add_row("Gateway", "Allow Synthetic Source IP", str(config.gateway.allow_synthetic_source_ip))

    table.add_row("Keycloak", "Base URL", config.keycloak.base_url)
    table.add_row("Keycloak", "Realm", config.keycloak.realm)
    table.add_row("Keycloak", "Client ID", config.keycloak.client_id)
    table.add_row("Keycloak", "Token Expiry Buffer (s)", str(config.keycloak.token_expiry_buffer_seconds))

    table.add_row("Downstream Health", "Customer Service URL", config.downstream_health.customer_service_url)
    table.add_row("Downstream Health", "Account Service URL", config.downstream_health.account_service_url)
    table.add_row("Downstream Health", "Transaction Service URL", config.downstream_health.transaction_service_url)

    table.add_row("Execution", "Environment ID", config.execution.environment_id)
    table.add_row("Execution", "Allow Non-Local Override", str(config.execution.allow_non_local))
    table.add_row("Execution", "Max Concurrency", str(config.execution.max_concurrency))

    identities_count = len(config.user_passwords)
    table.add_row("Security Context", "Configured User Credentials", f"{identities_count} identity secret(s) loaded")

    console.print(table)
    console.print(
        Panel(
            "[bold green][OK] Configuration is valid and strictly enforces local-only isolation safeguards.[/bold green]",
            border_style="green",
        )
    )


async def _probe_endpoint(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    health_path: str,
) -> tuple[str, str, str, float, str]:
    """Probes a service health endpoint non-mutatingly."""
    full_url = f"{url.rstrip('/')}{health_path}"
    start = time.perf_counter()
    try:
        resp = await client.get(full_url, timeout=3.0)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 1)
        if resp.status_code in (200, 204):
            return name, full_url, "UP", elapsed_ms, "Healthy"
        return name, full_url, "DEGRADED", elapsed_ms, f"HTTP {resp.status_code}"
    except httpx.ConnectError:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 1)
        return name, full_url, "DOWN", elapsed_ms, "Connection Refused"
    except httpx.TimeoutException:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 1)
        return name, full_url, "DOWN", elapsed_ms, "Probe Timed Out"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 1)
        return name, full_url, "DOWN", elapsed_ms, f"Error: {e}"


async def _run_doctor(config: SimulationConfig) -> list[tuple[str, str, str, float, str]]:
    """Runs concurrent health probes across all services."""
    services = [
        ("Aegis Gateway", config.gateway.base_url, "/actuator/health/readiness"),
        ("Keycloak IdP", config.keycloak.base_url, f"/realms/{config.keycloak.realm}/.well-known/openid-configuration"),
        ("Customer Service", config.downstream_health.customer_service_url, "/actuator/health/readiness"),
        ("Account Service", config.downstream_health.account_service_url, "/actuator/health/readiness"),
        ("Transaction Service", config.downstream_health.transaction_service_url, "/actuator/health/readiness"),
    ]

    async with httpx.AsyncClient() as client:
        tasks = [
            _probe_endpoint(client, name, url, path)
            for name, url, path in services
        ]
        return await asyncio.gather(*tasks)


@app.command("doctor")
def doctor_cmd(
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML configuration file",
    ),
) -> None:
    """Performs non-mutating connectivity checks against all local FinTech services."""
    try:
        config = load_config(config_path=config_file)
    except Exception as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    console.print("[dim]Probing local testbed service endpoints non-mutatingly...[/dim]")
    results = asyncio.run(_run_doctor(config))

    table = Table(title="Aegis Testbed Diagnostic Health Matrix", header_style="bold cyan")
    table.add_column("Service", style="bold white", width=22)
    table.add_column("Probe Target", style="dim", width=42)
    table.add_column("Status", width=12)
    table.add_column("Latency (ms)", justify="right", width=14)
    table.add_column("Details", style="white")

    all_healthy = True
    for name, target, status, latency, details in results:
        if status == "UP":
            status_cell = "[bold green][OK] UP[/bold green]"
        elif status == "DEGRADED":
            status_cell = "[bold yellow][WARN] DEGRADED[/bold yellow]"
            all_healthy = False
        else:
            status_cell = "[bold red][FAIL] DOWN[/bold red]"
            all_healthy = False

        table.add_row(name, target, status_cell, f"{latency} ms", details)

    console.print(table)

    if all_healthy:
        console.print(
            Panel(
                "[bold green][OK] All Aegis FinTech testbed services are reachable and healthy.[/bold green]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                "[bold yellow][WARN] Some testbed services are unreachable. Ensure containers are running with 'docker compose up -d'.[/bold yellow]",
                border_style="yellow",
            )
        )


@scenarios_app.command("list")
def scenarios_list_cmd() -> None:
    """Lists registered simulation scenario categories and implementation status."""
    registry = get_default_registry()
    scenarios = registry.list_all()

    table = Table(title="Aegis FinTech Simulation Scenarios", header_style="bold cyan")
    table.add_column("Scenario ID", style="bold magenta", no_wrap=True)
    table.add_column("Category", style="cyan")
    table.add_column("Scenario Name", style="white")
    table.add_column("Target Services", style="dim")
    table.add_column("Expected Rules", style="yellow")
    table.add_column("Status")

    for s in scenarios:
        targets = ", ".join(s.target_services) or "all"
        rules = ", ".join(s.expected_outcome.expected_detection_rules) or "none"
        if s.is_implemented:
            status_str = "[bold green]IMPLEMENTED[/bold green]"
        else:
            status_str = "[dim yellow]Planned (Phase 7.2.3)[/dim yellow]"

        table.add_row(
            s.id,
            s.category.value,
            s.name,
            targets,
            rules,
            status_str,
        )

    console.print(table)
    console.print(
        "[dim]Note: Executable traffic generation logic for scenarios will be introduced in Phase 7.2.3.[/dim]"
    )


if __name__ == "__main__":
    app()
