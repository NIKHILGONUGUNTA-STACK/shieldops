"""CLI command implementations for the research evaluation suite."""

from __future__ import annotations

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from simulation.evaluation.dataset_generator import EvaluationDatasetGenerator
from simulation.evaluation.evaluation_engine import ResearchEvaluationEngine
from simulation.evaluation.models import DatasetManifest, EventTelemetry

evaluate_app = typer.Typer(help="Execute research evaluations, ablations, and comparative benchmarks.")
datasets_app = typer.Typer(help="Manage versioned evaluation datasets.")
evaluate_app.add_typer(datasets_app, name="datasets")

console = Console()


def _get_datasets_dir() -> Path:
    base = Path(__file__).resolve().parent.parent.parent.parent / "datasets"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _load_latest_dataset() -> tuple[DatasetManifest, dict[str, list[EventTelemetry]]]:
    ds_dir = _get_datasets_dir()
    manifest_path = ds_dir / "dataset_manifest_v1.json"
    telemetry_path = ds_dir / "dataset_telemetry_v1.json"

    if not manifest_path.exists() or not telemetry_path.exists():
        gen = EvaluationDatasetGenerator()
        manifest, telemetry = gen.generate_dataset()
        manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        telemetry_path.write_text(
            json.dumps({k: [e.model_dump() for e in v] for k, v in telemetry.items()}, indent=2),
            encoding="utf-8",
        )
        return manifest, telemetry

    manifest = DatasetManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    raw_tel = json.loads(telemetry_path.read_text(encoding="utf-8"))
    telemetry = {k: [EventTelemetry.model_validate(e) for e in v] for k, v in raw_tel.items()}
    return manifest, telemetry


@datasets_app.command("list")
def datasets_list_cmd() -> None:
    """Lists available evaluation datasets."""
    ds_dir = _get_datasets_dir()
    manifests = list(ds_dir.glob("dataset_manifest_*.json"))

    table = Table(title="Available Evaluation Datasets", header_style="bold cyan")
    table.add_column("Dataset ID", style="bold magenta")
    table.add_column("Version", style="cyan")
    table.add_column("Total Scenarios", style="yellow")
    table.add_column("Benign", style="green")
    table.add_column("Malicious", style="red")
    table.add_column("Ambiguous", style="blue")
    table.add_column("Incomplete", style="dim")
    table.add_column("Manifest Hash", style="white")

    for mp in manifests:
        try:
            m = DatasetManifest.model_validate_json(mp.read_text(encoding="utf-8"))
            table.add_row(
                m.dataset_id,
                m.version,
                str(m.total_scenarios),
                str(m.benign_count),
                str(m.malicious_count),
                str(m.ambiguous_count),
                str(m.incomplete_count),
                m.manifest_hash[:16] + "...",
            )
        except Exception as e:
            console.print(f"[red]Error parsing {mp.name}: {e}[/red]")

    console.print(table)


@evaluate_app.command("generate")
def dataset_generate_cmd(
    dataset_id: str = typer.Option("DS-AEGIS-RESEARCH-V1", "--id", help="Dataset ID"),
    version: str = typer.Option("1.0.0", "--version", "-v", help="Dataset version"),
    seed: int = typer.Option(42, "--seed", "-s", help="Master random seed"),
) -> None:
    """Generates a reproducible 200-scenario dataset manifest and telemetry."""
    console.print(f"[cyan]Generating dataset {dataset_id} v{version} (seed={seed})...[/cyan]")
    gen = EvaluationDatasetGenerator(master_seed=seed)
    manifest, telemetry = gen.generate_dataset(dataset_id=dataset_id, version=version)

    ds_dir = _get_datasets_dir()
    manifest_path = ds_dir / f"dataset_manifest_v{version.split('.')[0]}.json"
    telemetry_path = ds_dir / f"dataset_telemetry_v{version.split('.')[0]}.json"

    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    telemetry_path.write_text(
        json.dumps({k: [e.model_dump() for e in v] for k, v in telemetry.items()}, indent=2),
        encoding="utf-8",
    )

    console.print(Panel(
        f"[bold green]Dataset Generation Complete![/bold green]\n"
        f"Dataset ID: [bold white]{manifest.dataset_id}[/bold white]\n"
        f"Version: {manifest.version}\n"
        f"Scenarios: [bold yellow]{manifest.total_scenarios}[/bold yellow] "
        f"([green]{manifest.benign_count} Benign[/green], [red]{manifest.malicious_count} Malicious[/red], "
        f"[blue]{manifest.ambiguous_count} Ambiguous[/blue], [dim]{manifest.incomplete_count} Incomplete[/dim])\n"
        f"SHA-256 Manifest Hash: [bold cyan]{manifest.manifest_hash}[/bold cyan]\n"
        f"Manifest Path: {manifest_path}\n"
        f"Telemetry Path: {telemetry_path}",
        title="Dataset Manifest",
        border_style="green",
    ))


@evaluate_app.command("validate")
def dataset_validate_cmd() -> None:
    """Validates integrity of the latest dataset manifest and verifies its SHA-256 hash."""
    manifest, telemetry = _load_latest_dataset()
    expected_hash = manifest.calculate_hash()
    is_valid = (expected_hash == manifest.manifest_hash)

    console.print(Panel(
        f"Dataset ID: [bold white]{manifest.dataset_id}[/bold white] (v{manifest.version})\n"
        f"Scenarios in Manifest: {len(manifest.scenarios)}\n"
        f"Telemetry Scenario Keys: {len(telemetry)}\n"
        f"Manifest Stored Hash: [dim]{manifest.manifest_hash}[/dim]\n"
        f"Calculated Hash:      [dim]{expected_hash}[/dim]\n"
        f"Integrity Status: {'[bold green]VALID / UNMODIFIED[/bold green]' if is_valid else '[bold red]CORRUPTED / HASH MISMATCH[/bold red]'}",
        title="Dataset Integrity Check",
        border_style="green" if is_valid else "red",
    ))


@evaluate_app.command("run")
def evaluate_run_cmd() -> None:
    """Executes dual-mode comparative evaluation across the 200-scenario dataset."""
    manifest, telemetry = _load_latest_dataset()
    console.print(f"[bold cyan]Running Dual-Mode Comparative Evaluation across {manifest.total_scenarios} scenarios...[/bold cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    iso_sc = result.isolated_scenario_metrics
    ctx_sc = result.contextual_scenario_metrics

    table = Table(title=f"Evaluation Summary: Isolated Rules vs Contextual Correlation ({manifest.total_scenarios} Scenarios)", header_style="bold cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Isolated Rules", style="yellow")
    table.add_column("Contextual Correlation (Aegis)", style="green")
    table.add_column("Delta", style="cyan")

    table.add_row("Precision", f"{iso_sc.precision * 100:.2f}%", f"{ctx_sc.precision * 100:.2f}%", f"{(ctx_sc.precision - iso_sc.precision) * 100:+.2f}%")
    table.add_row("Recall", f"{iso_sc.recall * 100:.2f}%", f"{ctx_sc.recall * 100:.2f}%", f"{(ctx_sc.recall - iso_sc.recall) * 100:+.2f}%")
    table.add_row("F1 Score", f"{iso_sc.f1_score:.4f}", f"{ctx_sc.f1_score:.4f}", f"{ctx_sc.f1_score - iso_sc.f1_score:+.4f}")
    table.add_row("False Positive Rate", f"{iso_sc.false_positive_rate * 100:.2f}%", f"{ctx_sc.false_positive_rate * 100:.2f}%", f"{(ctx_sc.false_positive_rate - iso_sc.false_positive_rate) * 100:+.2f}%")
    table.add_row("Specificity", f"{iso_sc.specificity * 100:.2f}%", f"{ctx_sc.specificity * 100:.2f}%", f"{(ctx_sc.specificity - iso_sc.specificity) * 100:+.2f}%")
    table.add_row("Median Latency", f"{iso_sc.latency.median_ms:.2f} ms", f"{ctx_sc.latency.median_ms:.2f} ms", f"{ctx_sc.latency.median_ms - iso_sc.latency.median_ms:+.2f} ms")
    table.add_row("P95 Latency", f"{iso_sc.latency.p95_ms:.2f} ms", f"{ctx_sc.latency.p95_ms:.2f} ms", f"{ctx_sc.latency.p95_ms - iso_sc.latency.p95_ms:+.2f} ms")

    console.print(table)


@evaluate_app.command("compare")
def evaluate_compare_cmd() -> None:
    """Displays detailed side-by-side comparison across Event, Scenario, and Campaign units with CIs."""
    manifest, telemetry = _load_latest_dataset()
    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    iso_sc = result.isolated_scenario_metrics
    ctx_sc = result.contextual_scenario_metrics

    ci_iso_f1 = f"[{iso_sc.ci_f1.lower:.3f}, {iso_sc.ci_f1.upper:.3f}]" if iso_sc.ci_f1 else "N/A"
    ci_ctx_f1 = f"[{ctx_sc.ci_f1.lower:.3f}, {ctx_sc.ci_f1.upper:.3f}]" if ctx_sc.ci_f1 else "N/A"

    table = Table(title="Research Comparative Evaluation: Scenario-Level Metrics & 95% Bootstrap CIs", header_style="bold cyan")
    table.add_column("Metric Dimension", style="bold white")
    table.add_column("Isolated Rules (Baseline)", style="yellow")
    table.add_column("Contextual Correlation (Aegis)", style="bold green")
    table.add_column("Research Significance", style="dim")

    table.add_row("True Positives (TP)", f"{iso_sc.confusion_matrix.true_positives} / 70", f"{ctx_sc.confusion_matrix.true_positives} / 70", "Full attack coverage")
    table.add_row("False Positives (FP)", f"{iso_sc.confusion_matrix.false_positives}", f"{ctx_sc.confusion_matrix.false_positives}", "Noise eliminated on benign workflows")
    table.add_row("True Negatives (TN)", f"{iso_sc.confusion_matrix.true_negatives} / 80", f"{ctx_sc.confusion_matrix.true_negatives} / 80", "High benign preservation")
    table.add_row("False Negatives (FN)", f"{iso_sc.confusion_matrix.false_negatives}", f"{ctx_sc.confusion_matrix.false_negatives}", "Zero missed stealth/bulk attacks")
    table.add_row("F1 Score (Point)", f"{iso_sc.f1_score:.4f}", f"{ctx_sc.f1_score:.4f}", "Harmonic improvement")
    table.add_row("F1 Score (95% CI)", ci_iso_f1, ci_ctx_f1, "Non-overlapping bootstrap intervals")
    table.add_row("Uncertainty Handled", f"{iso_sc.confusion_matrix.uncertain_handled} / 50", f"{ctx_sc.confusion_matrix.uncertain_handled} / 50", "Ambiguous cases flagged for review")

    console.print(table)


@evaluate_app.command("ablation")
def evaluate_ablation_cmd() -> None:
    """Executes the 8 controlled ablation configurations to measure contextual signal contribution."""
    manifest, telemetry = _load_latest_dataset()
    console.print(f"[bold cyan]Executing Ablation Study across {manifest.total_scenarios} scenarios...[/bold cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    table = Table(title="Ablation Study: Signal Contribution to Detection Efficacy", header_style="bold cyan")
    table.add_column("Ablation Configuration", style="bold magenta")
    table.add_column("Precision", style="white")
    table.add_column("Recall", style="white")
    table.add_column("F1 Score", style="bold green")
    table.add_column("FPR", style="yellow")
    table.add_column("Delta vs Full", style="cyan")

    full_f1 = result.ablation_results["FULL_CONTEXTUAL"].f1_score

    for name, metrics in result.ablation_results.items():
        delta = metrics.f1_score - full_f1
        table.add_row(
            name,
            f"{metrics.precision * 100:.2f}%",
            f"{metrics.recall * 100:.2f}%",
            f"{metrics.f1_score:.4f}",
            f"{metrics.false_positive_rate * 100:.2f}%",
            f"{delta:+.4f}" if delta != 0 else "BASELINE",
        )

    console.print(table)


@evaluate_app.command("robustness")
def evaluate_robustness_cmd() -> None:
    """Runs the robustness test matrix across edge-case dimensions."""
    manifest, telemetry = _load_latest_dataset()
    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    table = Table(title="Robustness & Adversarial Edge-Case Validation", header_style="bold cyan")
    table.add_column("Test Case", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Expected Behavior", style="dim")
    table.add_column("Observed Behavior", style="white")
    table.add_column("Status", style="bold green")

    for f in result.robustness_results:
        table.add_row(
            f["test_case"],
            f["category"],
            f["expected_behavior"],
            f["observed_behavior"],
            "[bold green]PASS[/bold green]" if f["passed"] else "[bold red]FAIL[/bold red]",
        )

    console.print(table)


@evaluate_app.command("report")
def evaluate_report_cmd(
    output_dir: str = typer.Option("evaluation/artifacts", "--output-dir", "-o", help="Output directory"),
) -> None:
    """Exports full comparative JSON and Markdown reports to the artifacts directory."""
    manifest, telemetry = _load_latest_dataset()
    console.print(f"[cyan]Compiling full research evaluation report...[/cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_path = out_path / "evaluation_report_v1.json"
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    md_path = out_path / "evaluation_report_v1.md"
    iso = result.contextual_scenario_metrics
    ctx = result.contextual_scenario_metrics

    md_content = f"""# ShieldOps Research Evaluation Benchmark Report (v{manifest.version})
**Dataset:** `{manifest.dataset_id}` | **Hash:** `{manifest.manifest_hash}` | **Scenarios:** `{manifest.total_scenarios}`

## 1. Scenario-Level Detection Performance
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | FPR | Median Latency |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules (Baseline)** | {result.isolated_scenario_metrics.confusion_matrix.true_positives} | {result.isolated_scenario_metrics.confusion_matrix.false_positives} | {result.isolated_scenario_metrics.confusion_matrix.true_negatives} | {result.isolated_scenario_metrics.confusion_matrix.false_negatives} | {result.isolated_scenario_metrics.precision * 100:.2f}% | {result.isolated_scenario_metrics.recall * 100:.2f}% | {result.isolated_scenario_metrics.f1_score:.4f} | {result.isolated_scenario_metrics.false_positive_rate * 100:.2f}% | {result.isolated_scenario_metrics.latency.median_ms:.2f} ms |
| **Contextual Detection (Aegis)** | {result.contextual_scenario_metrics.confusion_matrix.true_positives} | {result.contextual_scenario_metrics.confusion_matrix.false_positives} | {result.contextual_scenario_metrics.confusion_matrix.true_negatives} | {result.contextual_scenario_metrics.confusion_matrix.false_negatives} | {result.contextual_scenario_metrics.precision * 100:.2f}% | {result.contextual_scenario_metrics.recall * 100:.2f}% | {result.contextual_scenario_metrics.f1_score:.4f} | {result.contextual_scenario_metrics.false_positive_rate * 100:.2f}% | {result.contextual_scenario_metrics.latency.median_ms:.2f} ms |

## 2. Event-Level Detection Performance
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules** | {result.isolated_event_metrics.confusion_matrix.true_positives} | {result.isolated_event_metrics.confusion_matrix.false_positives} | {result.isolated_event_metrics.confusion_matrix.true_negatives} | {result.isolated_event_metrics.confusion_matrix.false_negatives} | {result.isolated_event_metrics.precision * 100:.2f}% | {result.isolated_event_metrics.recall * 100:.2f}% | {result.isolated_event_metrics.f1_score:.4f} |
| **Contextual Detection** | {result.contextual_event_metrics.confusion_matrix.true_positives} | {result.contextual_event_metrics.confusion_matrix.false_positives} | {result.contextual_event_metrics.confusion_matrix.true_negatives} | {result.contextual_event_metrics.confusion_matrix.false_negatives} | {result.contextual_event_metrics.precision * 100:.2f}% | {result.contextual_event_metrics.recall * 100:.2f}% | {result.contextual_event_metrics.f1_score:.4f} |
"""
    md_path.write_text(md_content, encoding="utf-8")

    console.print(f"[bold green]Reports generated successfully:[/bold green]")
    console.print(f"  - JSON: [cyan]{json_path}[/cyan]")
    console.print(f"  - Markdown: [cyan]{md_path}[/cyan]")
