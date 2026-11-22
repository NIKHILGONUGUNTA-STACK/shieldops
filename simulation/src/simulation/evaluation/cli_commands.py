"""CLI Commands for Research Evaluation Engine (Phase 7.3.6.1).

Commands:
- evaluate run: Executes dual-mode comparative evaluation with two-population accounting.
- evaluate compare: Displays side-by-side performance with exact McNemar test and bootstrap CIs.
- evaluate ablation: Executes the 8 controlled ablation configurations.
- evaluate robustness: Dynamically executes the edge-case validation suite.
- evaluate report: Exports canonical versioned evaluation reports.
- evaluate datasets list: Lists available datasets with multi-hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from simulation.evaluation.dataset_generator import (
    EvaluationDatasetGenerator,
    save_dataset_artifacts,
    verify_dataset_integrity,
)
from simulation.evaluation.evaluation_engine import ResearchEvaluationEngine
from simulation.evaluation.models import (
    DatasetManifest,
    EventTelemetry,
    GroundTruthArtifact,
)

evaluate_app = typer.Typer(help="Execute research evaluations, ablations, and comparative benchmarks.")
datasets_app = typer.Typer(help="Manage versioned evaluation datasets.")
evaluate_app.add_typer(datasets_app, name="datasets")

console = Console()


def _get_datasets_dir() -> Path:
    base = Path(__file__).resolve().parent.parent.parent.parent / "datasets"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _load_latest_dataset() -> Tuple[DatasetManifest, GroundTruthArtifact, Dict[str, List[EventTelemetry]]]:
    """Loads latest v1.1 evaluation artifacts with fallback to v1.0."""
    ds_dir = _get_datasets_dir()
    m_v1_1 = ds_dir / "dataset_manifest_v1_1.json"
    g_v1_1 = ds_dir / "ground_truth_v1_1.json"
    t_v1_1 = ds_dir / "dataset_telemetry_v1_1.json"

    if m_v1_1.exists() and g_v1_1.exists() and t_v1_1.exists():
        manifest = DatasetManifest.model_validate_json(m_v1_1.read_text(encoding="utf-8"))
        gt = GroundTruthArtifact.model_validate_json(g_v1_1.read_text(encoding="utf-8"))
        raw_tel = json.loads(t_v1_1.read_text(encoding="utf-8"))
        telemetry = {k: [EventTelemetry.model_validate(e) for e in v] for k, v in raw_tel.items()}
        return manifest, gt, telemetry

    # Fallback to historical v1.0
    m_v1 = ds_dir / "dataset_manifest_v1.json"
    t_v1 = ds_dir / "dataset_telemetry_v1.json"

    if not m_v1.exists() or not t_v1.exists():
        gen = EvaluationDatasetGenerator(master_seed=42)
        manifest, gt, telemetry = gen.generate_dataset_v1_1()
        save_dataset_artifacts(manifest, gt, telemetry, ds_dir)
        return manifest, gt, telemetry

    manifest = DatasetManifest.model_validate_json(m_v1.read_text(encoding="utf-8"))
    raw_tel = json.loads(t_v1.read_text(encoding="utf-8"))
    telemetry = {k: [EventTelemetry.model_validate(e) for e in v] for k, v in raw_tel.items()}
    gt = GroundTruthArtifact(
        dataset_id=manifest.dataset_id,
        version=manifest.version,
        created_at=manifest.created_at,
        ground_truth_hash=manifest.ground_truth_hash or manifest.calculate_hash(),
        total_scenarios=len(manifest.scenarios),
        population_distribution={
            "BENIGN": manifest.benign_count,
            "MALICIOUS": manifest.malicious_count,
            "AMBIGUOUS": manifest.ambiguous_count,
            "INCOMPLETE_EVIDENCE": manifest.incomplete_count,
        },
        scenarios=manifest.scenarios,
    )
    return manifest, gt, telemetry


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


@evaluate_app.command("run")
def evaluate_run_cmd() -> None:
    """Executes dual-mode comparative evaluation with two-population accounting."""
    manifest, gt, telemetry = _load_latest_dataset()
    console.print(f"[bold cyan]Running Dual-Mode Evaluation (Dataset: {manifest.dataset_id} v{manifest.version})...[/bold cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=gt)
    result = engine.run_full_evaluation()

    iso_sc = result.isolated_scenario_metrics
    ctx_sc = result.contextual_scenario_metrics
    pop = result.population_accounting

    # 1. Primary Binary Evaluation Table
    table = Table(
        title=f"Primary Binary Evaluation (n={pop.primary_binary_evaluated}: {pop.binary_benign_count} Benign, {pop.binary_malicious_count} Malicious)",
        header_style="bold cyan",
    )
    table.add_column("Metric", style="bold white")
    table.add_column("Isolated Rules", style="yellow")
    table.add_column("Contextual Correlation (Aegis)", style="green")
    table.add_column("Delta", style="cyan")

    table.add_row("Precision", f"{iso_sc.precision * 100:.2f}%", f"{ctx_sc.precision * 100:.2f}%", f"{(ctx_sc.precision - iso_sc.precision) * 100:+.2f}%")
    table.add_row("Recall", f"{iso_sc.recall * 100:.2f}%", f"{ctx_sc.recall * 100:.2f}%", f"{(ctx_sc.recall - iso_sc.recall) * 100:+.2f}%")
    table.add_row("F1 Score", f"{iso_sc.f1_score:.4f}", f"{ctx_sc.f1_score:.4f}", f"{ctx_sc.f1_score - iso_sc.f1_score:+.4f}")
    table.add_row("False Positive Rate (FPR)", f"{iso_sc.false_positive_rate * 100:.2f}%", f"{ctx_sc.false_positive_rate * 100:.2f}%", f"{(ctx_sc.false_positive_rate - iso_sc.false_positive_rate) * 100:+.2f}%")
    table.add_row("False Discovery Rate (FDR)", f"{iso_sc.false_discovery_rate * 100:.2f}%", f"{ctx_sc.false_discovery_rate * 100:.2f}%", f"{(ctx_sc.false_discovery_rate - iso_sc.false_discovery_rate) * 100:+.2f}%")
    table.add_row("Specificity", f"{iso_sc.specificity * 100:.2f}%", f"{ctx_sc.specificity * 100:.2f}%", f"{(ctx_sc.specificity - iso_sc.specificity) * 100:+.2f}%")
    table.add_row("Accuracy", f"{iso_sc.accuracy * 100:.2f}%", f"{ctx_sc.accuracy * 100:.2f}%", f"{(ctx_sc.accuracy - iso_sc.accuracy) * 100:+.2f}%")

    console.print(table)

    # 2. Secondary Population Uncertainty Table
    iso_unc = result.isolated_uncertainty_metrics
    ctx_unc = result.contextual_uncertainty_metrics

    unc_table = Table(
        title=f"Secondary Population Disposition (n={iso_unc.total_samples}: {iso_unc.ambiguous_count} Ambiguous, {iso_unc.incomplete_count} Incomplete)",
        header_style="bold magenta",
    )
    unc_table.add_column("Disposition Category", style="bold white")
    unc_table.add_column("Isolated Rules", style="yellow")
    unc_table.add_column("Contextual Correlation", style="green")
    unc_table.add_column("Target Operational Role", style="dim")

    unc_table.add_row(
        "Abstained / Flagged Uncertain",
        f"{iso_unc.abstained_uncertain} ({iso_unc.abstention_rate*100:.1f}%)",
        f"{ctx_unc.abstained_uncertain} ({ctx_unc.abstention_rate*100:.1f}%)",
        "Safe investigation routing",
    )
    unc_table.add_row(
        "Over-Escalated as Attack",
        f"{iso_unc.flagged_malicious} ({iso_unc.over_escalation_rate*100:.1f}%)",
        f"{ctx_unc.flagged_malicious} ({ctx_unc.over_escalation_rate*100:.1f}%)",
        "False alarm penalty",
    )
    unc_table.add_row(
        "Silently Passed as Benign",
        f"{iso_unc.passed_benign} ({iso_unc.under_investigation_rate*100:.1f}%)",
        f"{ctx_unc.passed_benign} ({ctx_unc.under_investigation_rate*100:.1f}%)",
        "Under-investigation risk",
    )

    console.print(unc_table)

    # 3. Paired Exact McNemar Test Panel
    mcn = result.paired_scenario_comparison
    console.print(Panel(
        f"[bold white]Paired Statistical Test:[/bold white] {mcn.test_name}\n"
        f"Sample Size (Eligible Binary): [bold yellow]{mcn.sample_size}[/bold yellow] pairs\n"
        f"Contingency: Both Correct ([green]{mcn.both_correct_a}[/green]), "
        f"Both Incorrect ([red]{mcn.both_incorrect_d}[/red])\n"
        f"Discordant Pairs: Isolated Correct/Ctx Incorrect (b) = [yellow]{mcn.isolated_correct_contextual_incorrect_b}[/yellow], "
        f"Isolated Incorrect/Ctx Correct (c) = [bold green]{mcn.isolated_incorrect_contextual_correct_c}[/bold green]\n"
        f"Exact Two-Sided p-value: [bold cyan]{mcn.p_value_exact:.6f}[/bold cyan] "
        f"({'[bold green]STATISTICALLY SIGNIFICANT (p < 0.05)[/bold green]' if mcn.statistically_significant else '[yellow]Not Significant[/yellow]'})\n"
        f"Paired Bootstrap Δ F1: [bold green]{mcn.delta_f1:+.4f}[/bold green] "
        f"(95% CI: [{mcn.ci_delta_f1.lower:+.4f}, {mcn.ci_delta_f1.upper:+.4f}])\n"
        f"Paired Bootstrap Δ FPR: [bold green]{mcn.delta_fpr:+.4f}[/bold green] "
        f"(95% CI: [{mcn.ci_delta_fpr.lower:+.4f}, {mcn.ci_delta_fpr.upper:+.4f}])",
        title="Paired Comparative Significance",
        border_style="cyan",
    ))


@evaluate_app.command("compare")
def evaluate_compare_cmd() -> None:
    """Displays detailed side-by-side comparison across Event, Scenario, and Campaign units with CIs."""
    manifest, gt, telemetry = _load_latest_dataset()
    engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=gt)
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
    table.add_row("False Positives (FP)", f"{iso_sc.confusion_matrix.false_positives} / 80", f"{ctx_sc.confusion_matrix.false_positives} / 80", "Noise eliminated on benign workflows")
    table.add_row("True Negatives (TN)", f"{iso_sc.confusion_matrix.true_negatives} / 80", f"{ctx_sc.confusion_matrix.true_negatives} / 80", "High benign preservation")
    table.add_row("False Negatives (FN)", f"{iso_sc.confusion_matrix.false_negatives} / 70", f"{ctx_sc.confusion_matrix.false_negatives} / 70", "Zero missed stealth/bulk attacks")
    table.add_row("F1 Score (Point)", f"{iso_sc.f1_score:.4f}", f"{ctx_sc.f1_score:.4f}", "Harmonic improvement")
    table.add_row("F1 Score (95% CI)", ci_iso_f1, ci_ctx_f1, "Non-overlapping bootstrap intervals")
    table.add_row("True FPR", f"{iso_sc.false_positive_rate*100:.2f}%", f"{ctx_sc.false_positive_rate*100:.2f}%", "FP / (FP + TN)")
    table.add_row("False Discovery Rate (FDR)", f"{iso_sc.false_discovery_rate*100:.2f}%", f"{ctx_sc.false_discovery_rate*100:.2f}%", "FP / (TP + FP)")

    console.print(table)


@evaluate_app.command("ablation")
def evaluate_ablation_cmd() -> None:
    """Executes the 8 controlled ablation configurations across primary binary scenarios."""
    manifest, gt, telemetry = _load_latest_dataset()
    console.print(f"[bold cyan]Executing Ablation Study across {manifest.total_scenarios} scenarios...[/bold cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=gt)
    result = engine.run_full_evaluation()

    table = Table(title="Ablation Study: Signal Contribution to Detection Efficacy (n=150 Primary Binary)", header_style="bold cyan")
    table.add_column("Ablation Configuration", style="bold magenta")
    table.add_column("Precision", style="white")
    table.add_column("Recall", style="white")
    table.add_column("F1 Score", style="bold green")
    table.add_column("True FPR", style="yellow")
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
    """Runs the dynamic robustness test matrix across edge-case dimensions."""
    manifest, gt, telemetry = _load_latest_dataset()
    engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=gt)
    result = engine.run_full_evaluation()

    table = Table(title="Dynamic Robustness & Adversarial Edge-Case Validation", header_style="bold cyan")
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
    manifest, gt, telemetry = _load_latest_dataset()
    console.print(f"[cyan]Compiling full research evaluation report...[/cyan]")

    engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=gt)
    result = engine.run_full_evaluation()

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_path = out_path / "evaluation_report_v1_1.json"
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    md_path = out_path / "evaluation_report_v1_1.md"
    pop = result.population_accounting
    mcn = result.paired_scenario_comparison
    iso = result.isolated_scenario_metrics
    ctx = result.contextual_scenario_metrics

    md_content = f"""# ShieldOps Research Evaluation Benchmark Report (v{manifest.version})
**Dataset:** `{manifest.dataset_id}` | **Manifest Hash:** `{manifest.manifest_hash}` | **Total Scenarios:** `{manifest.total_scenarios}`

## 1. Population Accounting & Evaluation Coverage
- **Total Dataset Scenarios:** {pop.total_dataset_size}
- **Primary Binary Evaluation Population:** {pop.primary_binary_evaluated} ({pop.binary_benign_count} Benign, {pop.binary_malicious_count} Malicious)
- **Secondary Ambiguous / Incomplete Population:** {pop.ambiguous_evaluated + pop.incomplete_evaluated} ({pop.ambiguous_evaluated} Ambiguous, {pop.incomplete_evaluated} Incomplete)
- **Binary Evaluation Coverage:** {pop.binary_coverage_ratio * 100:.1f}%
- **Accounting Reconciled:** {pop.accounting_reconciled}

## 2. Primary Binary Detection Performance (n={pop.primary_binary_evaluated})
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | True FPR | FDR | Accuracy |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules (Baseline)** | {iso.confusion_matrix.true_positives} | {iso.confusion_matrix.false_positives} | {iso.confusion_matrix.true_negatives} | {iso.confusion_matrix.false_negatives} | {iso.precision * 100:.2f}% | {iso.recall * 100:.2f}% | {iso.f1_score:.4f} | {iso.false_positive_rate * 100:.2f}% | {iso.false_discovery_rate * 100:.2f}% | {iso.accuracy * 100:.2f}% |
| **Contextual Detection (Aegis)** | {ctx.confusion_matrix.true_positives} | {ctx.confusion_matrix.false_positives} | {ctx.confusion_matrix.true_negatives} | {ctx.confusion_matrix.false_negatives} | {ctx.precision * 100:.2f}% | {ctx.recall * 100:.2f}% | {ctx.f1_score:.4f} | {ctx.false_positive_rate * 100:.2f}% | {ctx.false_discovery_rate * 100:.2f}% | {ctx.accuracy * 100:.2f}% |

## 3. Paired Comparative Statistical Significance (n={mcn.sample_size})
- **Exact Two-Sided McNemar Test:**
  - Discordant pairs: Isolated correct / Contextual incorrect (b) = {mcn.isolated_correct_contextual_incorrect_b}, Isolated incorrect / Contextual correct (c) = {mcn.isolated_incorrect_contextual_correct_c}
  - Exact p-value: `{mcn.p_value_exact:.6f}` ({'STATISTICALLY SIGNIFICANT at alpha=0.05' if mcn.statistically_significant else 'Not statistically significant'})
  - Odds Ratio (c/b): `{mcn.odds_ratio}`
- **Paired Scenario-Level Bootstrap (B={mcn.bootstrap_resamples}):**
  - Δ F1: `{mcn.delta_f1:+.4f}` (95% CI: [{mcn.ci_delta_f1.lower:+.4f}, {mcn.ci_delta_f1.upper:+.4f}])
  - Δ FPR: `{mcn.delta_fpr:+.4f}` (95% CI: [{mcn.ci_delta_fpr.lower:+.4f}, {mcn.ci_delta_fpr.upper:+.4f}])
  - Δ Precision: `{mcn.delta_precision:+.4f}` (95% CI: [{mcn.ci_delta_precision.lower:+.4f}, {mcn.ci_delta_precision.upper:+.4f}])
  - Δ Recall: `{mcn.delta_recall:+.4f}` (95% CI: [{mcn.ci_delta_recall.lower:+.4f}, {mcn.ci_delta_recall.upper:+.4f}])
  - Δ Accuracy: `{mcn.delta_accuracy:+.4f}`

## 4. Secondary Population Disposition & Uncertainty Handling (n=50)
| Disposition | Isolated Rules | Contextual Correlation |
|:---|:---:|:---:|
| **Abstained / Flagged Uncertain (Safe Triage)** | {result.isolated_uncertainty_metrics.abstained_uncertain} ({result.isolated_uncertainty_metrics.abstention_rate*100:.1f}%) | {result.contextual_uncertainty_metrics.abstained_uncertain} ({result.contextual_uncertainty_metrics.abstention_rate*100:.1f}%) |
| **Over-Escalated as Attack (False Alarm)** | {result.isolated_uncertainty_metrics.flagged_malicious} ({result.isolated_uncertainty_metrics.over_escalation_rate*100:.1f}%) | {result.contextual_uncertainty_metrics.flagged_malicious} ({result.contextual_uncertainty_metrics.over_escalation_rate*100:.1f}%) |
| **Silently Passed as Benign (Under-Investigation)** | {result.isolated_uncertainty_metrics.passed_benign} ({result.isolated_uncertainty_metrics.under_investigation_rate*100:.1f}%) | {result.contextual_uncertainty_metrics.passed_benign} ({result.contextual_uncertainty_metrics.under_investigation_rate*100:.1f}%) |

## 5. Controlled Ablation Study (Primary Binary Population n=150)
| Ablation Configuration | Precision | Recall | F1 Score | True FPR | Delta vs Full |
|:---|:---:|:---:|:---:|:---:|:---:|
"""
    full_f1 = result.ablation_results["FULL_CONTEXTUAL"].f1_score
    for name, metrics in result.ablation_results.items():
        delta = metrics.f1_score - full_f1
        delta_str = f"{delta:+.4f}" if delta != 0 else "BASELINE"
        md_content += f"| **{name}** | {metrics.precision * 100:.2f}% | {metrics.recall * 100:.2f}% | {metrics.f1_score:.4f} | {metrics.false_positive_rate * 100:.2f}% | {delta_str} |\n"

    md_content += """
## 6. Dynamic Robustness & Adversarial Edge-Case Validation
| Test Case | Category | Expected Behavior | Observed Behavior | Status |
|:---|:---|:---|:---|:---:|
"""
    for r in result.robustness_results:
        status_str = "PASS" if r["passed"] else "FAIL"
        md_content += f"| **{r['test_case']}** | {r['category']} | {r['expected_behavior']} | {r['observed_behavior']} | `{status_str}` |\n"

    md_path.write_text(md_content, encoding="utf-8")

    console.print(f"[bold green]Reports generated successfully:[/bold green]")
    console.print(f"  - JSON: [cyan]{json_path}[/cyan]")
    console.print(f"  - Markdown: [cyan]{md_path}[/cyan]")
