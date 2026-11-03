"""Aegis Simulation Command Line Interface (CLI).

Provides operational commands for configuration validation, environment health checks,
scenario listing, and framework diagnostics using Typer and Rich.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Optional
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from simulation import __version__
from simulation.config import SimulationConfig, load_config
from simulation.scenarios.registry import get_default_registry

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
        f"[green]v{__version__}[/green] [dim](Phase 7.2.2 Foundation)[/dim]"
    )


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
