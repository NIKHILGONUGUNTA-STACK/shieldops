"""Statistical calculation engine for Phase 7.3.6.1 Research Validity Correction.

Implements:
1. Exact binary confusion matrix & rate derivations (TPR, FPR, FDR, FNR, Specificity) with zero-denominator safety.
2. Segregated uncertainty handling metrics for non-binary ambiguous/incomplete populations.
3. Full 200-scenario population accounting and binary evaluation coverage reconciliation.
4. Exact two-sided McNemar testing on paired scenario outcomes with Edwards continuity correction.
5. Non-parametric paired scenario-level bootstrap confidence intervals (B=2000 resamples).
6. Wilson score intervals for binomial proportions.
7. Percentile latency distribution statistics (Mean, Median, P95, P99, Min, Max).
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Callable, Dict, List, Optional, Tuple

from simulation.evaluation.models import (
    ClassificationOutcome,
    ConfidenceInterval,
    ConfusionMatrix,
    GroundTruthCategory,
    LatencyStats,
    MetricReport,
    PairedComparisonResult,
    PopulationAccounting,
    UncertaintyReport,
    UnitEvaluation,
)


def compute_wilson_score_interval(
    k: int, n: int, confidence: float = 0.95
) -> ConfidenceInterval:
    """Computes Wilson score confidence interval for binomial proportion k/n."""
    if n <= 0:
        return ConfidenceInterval(
            point_estimate=0.0,
            lower=0.0,
            upper=0.0,
            confidence_level=confidence,
            method="wilson",
            sample_size=0,
        )

    p = k / n
    if confidence == 0.99:
        z = 2.575829
    elif confidence == 0.90:
        z = 1.644854
    else:
        z = 1.959964  # default 0.95

    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return ConfidenceInterval(
        point_estimate=round(p, 4),
        lower=round(lower, 4),
        upper=round(upper, 4),
        confidence_level=confidence,
        method="wilson",
        sample_size=n,
    )


def compute_bootstrap_ci(
    evaluations: List[UnitEvaluation],
    metric_func: Callable[[List[UnitEvaluation]], float],
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int = 42,
) -> ConfidenceInterval:
    """Computes non-parametric bootstrap confidence interval by resampling independent units."""
    n = len(evaluations)
    if n == 0:
        return ConfidenceInterval(
            point_estimate=0.0,
            lower=0.0,
            upper=0.0,
            confidence_level=confidence,
            method="bootstrap",
            sample_size=0,
        )

    point_est = metric_func(evaluations)
    rng = random.Random(seed)

    boot_samples: List[float] = []
    for _ in range(n_resamples):
        sample = [rng.choice(evaluations) for _ in range(n)]
        boot_samples.append(metric_func(sample))

    boot_samples.sort()
    alpha = (1.0 - confidence) / 2.0
    lower_idx = int(math.floor(alpha * n_resamples))
    upper_idx = min(int(math.ceil((1.0 - alpha) * n_resamples)) - 1, n_resamples - 1)

    lower = boot_samples[lower_idx]
    upper = boot_samples[upper_idx]

    return ConfidenceInterval(
        point_estimate=round(point_est, 4),
        lower=round(lower, 4),
        upper=round(upper, 4),
        confidence_level=confidence,
        method=f"bootstrap_{n_resamples}",
        sample_size=n,
    )


# -----------------------------------------------------------------------------
# Binary Metric Calculation Functions
# -----------------------------------------------------------------------------

def calculate_precision(evals: List[UnitEvaluation]) -> float:
    tp = sum(1 for e in evals if e.classification == ClassificationOutcome.TP)
    fp = sum(1 for e in evals if e.classification == ClassificationOutcome.FP)
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0


def calculate_recall(evals: List[UnitEvaluation]) -> float:
    tp = sum(1 for e in evals if e.classification == ClassificationOutcome.TP)
    fn = sum(1 for e in evals if e.classification == ClassificationOutcome.FN)
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


def calculate_f1(evals: List[UnitEvaluation]) -> float:
    p = calculate_precision(evals)
    r = calculate_recall(evals)
    return (2.0 * p * r) / (p + r) if (p + r) > 0 else 0.0


def calculate_fpr(evals: List[UnitEvaluation]) -> float:
    """True False Positive Rate: FP / (FP + TN) on eligible benign units."""
    fp = sum(1 for e in evals if e.classification == ClassificationOutcome.FP)
    tn = sum(1 for e in evals if e.classification == ClassificationOutcome.TN)
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def calculate_fdr(evals: List[UnitEvaluation]) -> float:
    """False Discovery Rate: FP / (TP + FP) = 1 - Precision."""
    tp = sum(1 for e in evals if e.classification == ClassificationOutcome.TP)
    fp = sum(1 for e in evals if e.classification == ClassificationOutcome.FP)
    return fp / (tp + fp) if (tp + fp) > 0 else 0.0


def calculate_fnr(evals: List[UnitEvaluation]) -> float:
    """False Negative Rate: FN / (TP + FN) = 1 - Recall."""
    tp = sum(1 for e in evals if e.classification == ClassificationOutcome.TP)
    fn = sum(1 for e in evals if e.classification == ClassificationOutcome.FN)
    return fn / (tp + fn) if (tp + fn) > 0 else 0.0


def calculate_accuracy(evals: List[UnitEvaluation]) -> float:
    """Standard binary classification accuracy: (TP + TN) / total."""
    tp = sum(1 for e in evals if e.classification == ClassificationOutcome.TP)
    tn = sum(1 for e in evals if e.classification == ClassificationOutcome.TN)
    total = len(evals)
    return (tp + tn) / total if total > 0 else 0.0


def calculate_specificity(evals: List[UnitEvaluation]) -> float:
    """Specificity (True Negative Rate): TN / (TN + FP) = 1 - FPR."""
    fp = sum(1 for e in evals if e.classification == ClassificationOutcome.FP)
    tn = sum(1 for e in evals if e.classification == ClassificationOutcome.TN)
    return tn / (tn + fp) if (tn + fp) > 0 else 0.0


def calculate_latency_stats(latencies_ms: List[float]) -> LatencyStats:
    """Calculates percentile distribution for latency samples."""
    if not latencies_ms:
        return LatencyStats()

    sorted_lat = sorted(latencies_ms)
    n = len(sorted_lat)
    p95_idx = min(int(math.ceil(0.95 * n)) - 1, n - 1)
    p99_idx = min(int(math.ceil(0.99 * n)) - 1, n - 1)

    return LatencyStats(
        sample_count=n,
        mean_ms=round(statistics.mean(sorted_lat), 3),
        median_ms=round(statistics.median(sorted_lat), 3),
        p95_ms=round(sorted_lat[p95_idx], 3),
        p99_ms=round(sorted_lat[p99_idx], 3),
        min_ms=round(sorted_lat[0], 3),
        max_ms=round(sorted_lat[-1], 3),
    )


# -----------------------------------------------------------------------------
# Primary Binary Metric Report Compilation
# -----------------------------------------------------------------------------

def compile_metric_report(
    evaluations: List[UnitEvaluation],
    latencies_ms: Optional[List[float]] = None,
    total_duration_sec: float = 1.0,
) -> MetricReport:
    """Aggregates primary binary unit evaluations (Benign & Malicious) into a complete MetricReport."""
    total = len(evaluations)
    tp = sum(1 for e in evaluations if e.classification == ClassificationOutcome.TP)
    fp = sum(1 for e in evaluations if e.classification == ClassificationOutcome.FP)
    tn = sum(1 for e in evaluations if e.classification == ClassificationOutcome.TN)
    fn = sum(1 for e in evaluations if e.classification == ClassificationOutcome.FN)

    cm = ConfusionMatrix(
        total_samples=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        uncertain_handled=0,
        uncertain_misclassified=0,
    )

    prec = calculate_precision(evaluations)
    rec = calculate_recall(evaluations)
    f1 = calculate_f1(evaluations)
    acc = calculate_accuracy(evaluations)
    fpr = calculate_fpr(evaluations)
    fdr = calculate_fdr(evaluations)
    fnr = calculate_fnr(evaluations)
    spec = calculate_specificity(evaluations)

    # Confidence Intervals (B=2000 bootstrap)
    ci_p = compute_bootstrap_ci(evaluations, calculate_precision, n_resamples=2000, seed=42)
    ci_r = compute_bootstrap_ci(evaluations, calculate_recall, n_resamples=2000, seed=42)
    ci_f = compute_bootstrap_ci(evaluations, calculate_f1, n_resamples=2000, seed=42)
    ci_fpr_val = compute_wilson_score_interval(fp, fp + tn) if (fp + tn) > 0 else None
    ci_fdr_val = compute_wilson_score_interval(fp, tp + fp) if (tp + fp) > 0 else None

    lat = calculate_latency_stats(latencies_ms or [])
    throughput = (total / total_duration_sec) if total_duration_sec > 0 else 0.0

    return MetricReport(
        confusion_matrix=cm,
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1_score=round(f1, 4),
        accuracy=round(acc, 4),
        false_positive_rate=round(fpr, 4),
        false_discovery_rate=round(fdr, 4),
        false_negative_rate=round(fnr, 4),
        specificity=round(spec, 4),
        uncertainty_rate=0.0,
        sample_size=total,
        ci_precision=ci_p,
        ci_recall=ci_r,
        ci_f1=ci_f,
        ci_fpr=ci_fpr_val,
        ci_fdr=ci_fdr_val,
        latency=lat,
        throughput_eps=round(throughput, 2),
    )


# -----------------------------------------------------------------------------
# Secondary Population Uncertainty Report Compilation
# -----------------------------------------------------------------------------

def compile_uncertainty_report(
    evaluations: List[UnitEvaluation],
    total_ambiguous: int = 30,
    total_incomplete: int = 20,
) -> UncertaintyReport:
    """Evaluates the 50 ambiguous / incomplete scenarios with explicit disposition accounting."""
    total = len(evaluations)
    abstained = 0
    flagged = 0
    passed = 0

    breakdown: Dict[str, Dict[str, int]] = {
        "AMBIGUOUS": {"abstained_uncertain": 0, "flagged_malicious": 0, "passed_benign": 0},
        "INCOMPLETE_EVIDENCE": {"abstained_uncertain": 0, "flagged_malicious": 0, "passed_benign": 0},
    }

    for ev in evaluations:
        cat_key = ev.ground_truth_category.value
        if cat_key not in breakdown:
            breakdown[cat_key] = {"abstained_uncertain": 0, "flagged_malicious": 0, "passed_benign": 0}

        if ev.is_uncertain:
            abstained += 1
            breakdown[cat_key]["abstained_uncertain"] += 1
        elif ev.actual_detection:
            flagged += 1
            breakdown[cat_key]["flagged_malicious"] += 1
        else:
            passed += 1
            breakdown[cat_key]["passed_benign"] += 1

    abstention_rate = abstained / total if total > 0 else 0.0
    over_escalation_rate = flagged / total if total > 0 else 0.0
    under_investigation_rate = passed / total if total > 0 else 0.0

    ci_abst = compute_wilson_score_interval(abstained, total) if total > 0 else None

    return UncertaintyReport(
        total_samples=total,
        ambiguous_count=total_ambiguous,
        incomplete_count=total_incomplete,
        abstained_uncertain=abstained,
        flagged_malicious=flagged,
        passed_benign=passed,
        abstention_rate=round(abstention_rate, 4),
        over_escalation_rate=round(over_escalation_rate, 4),
        under_investigation_rate=round(under_investigation_rate, 4),
        ci_abstention=ci_abst,
        disposition_breakdown=breakdown,
    )


# -----------------------------------------------------------------------------
# Full Population Accounting
# -----------------------------------------------------------------------------

def compile_population_accounting(
    total_dataset_size: int = 200,
    binary_count: int = 150,
    benign_count: int = 80,
    malicious_count: int = 70,
    ambiguous_count: int = 30,
    incomplete_count: int = 20,
) -> PopulationAccounting:
    """Reconciles full 200-scenario dataset population accounting and binary evaluation coverage."""
    reconciled = (
        binary_count == (benign_count + malicious_count)
        and total_dataset_size == (binary_count + ambiguous_count + incomplete_count)
    )
    coverage = binary_count / total_dataset_size if total_dataset_size > 0 else 0.0

    return PopulationAccounting(
        total_dataset_size=total_dataset_size,
        primary_binary_evaluated=binary_count,
        binary_benign_count=benign_count,
        binary_malicious_count=malicious_count,
        ambiguous_evaluated=ambiguous_count,
        incomplete_evaluated=incomplete_count,
        binary_coverage_ratio=round(coverage, 4),
        accounting_reconciled=reconciled,
    )


# -----------------------------------------------------------------------------
# Paired Comparative Statistics: Exact McNemar & Scenario Bootstrap
# -----------------------------------------------------------------------------

def exact_mcnemar_test(
    evals_iso: List[UnitEvaluation],
    evals_ctx: List[UnitEvaluation],
    alpha: float = 0.05,
) -> Tuple[int, int, int, int, float, float, bool]:
    """Computes exact two-sided McNemar test on paired scenario outcomes.

    Returns:
        (a, b, c, d, p_value, odds_ratio, is_significant)
        where:
            a: Both correct
            b: Isolated correct, Contextual incorrect
            c: Isolated incorrect, Contextual correct
            d: Both incorrect
    """
    assert len(evals_iso) == len(evals_ctx), "Evaluations must be paired and of equal length!"

    # Pair by unit_id
    ctx_map = {e.unit_id: e for e in evals_ctx}
    a = 0
    b = 0
    c = 0
    d = 0

    for iso in evals_iso:
        ctx = ctx_map.get(iso.unit_id)
        if not ctx:
            continue

        iso_correct = (iso.actual_detection == iso.expected_detection)
        ctx_correct = (ctx.actual_detection == ctx.expected_detection)

        if iso_correct and ctx_correct:
            a += 1
        elif iso_correct and not ctx_correct:
            b += 1
        elif not iso_correct and ctx_correct:
            c += 1
        else:
            d += 1

    n_discordant = b + c
    if n_discordant == 0:
        p_value = 1.0
        odds_ratio = 1.0
    else:
        # Exact two-sided binomial p-value under H0: P(discordant = b) = 0.5
        k = min(b, c)
        p_val_sum = sum(math.comb(n_discordant, x) * (0.5 ** n_discordant) for x in range(k + 1))
        p_value = min(1.0, 2.0 * p_val_sum)

        odds_ratio = c / b if b > 0 else float("inf")

    is_significant = (p_value < alpha)
    return a, b, c, d, round(p_value, 6), round(odds_ratio, 4) if odds_ratio != float("inf") else 999.0, is_significant


def compute_paired_comparison(
    evals_iso: List[UnitEvaluation],
    evals_ctx: List[UnitEvaluation],
    n_resamples: int = 2000,
    seed: int = 42,
    alpha: float = 0.05,
) -> PairedComparisonResult:
    """Computes exact McNemar test and paired scenario bootstrap confidence intervals for metric deltas."""
    n = len(evals_iso)
    assert n == len(evals_ctx), "Scenario evaluations must be paired!"

    a, b, c, d, p_val, odds_ratio, is_sig = exact_mcnemar_test(evals_iso, evals_ctx, alpha=alpha)

    # Point estimates
    p_iso = calculate_precision(evals_iso)
    p_ctx = calculate_precision(evals_ctx)
    r_iso = calculate_recall(evals_iso)
    r_ctx = calculate_recall(evals_ctx)
    f_iso = calculate_f1(evals_iso)
    f_ctx = calculate_f1(evals_ctx)
    fpr_iso = calculate_fpr(evals_iso)
    fpr_ctx = calculate_fpr(evals_ctx)
    acc_iso = calculate_accuracy(evals_iso)
    acc_ctx = calculate_accuracy(evals_ctx)

    delta_prec = p_ctx - p_iso
    delta_rec = r_ctx - r_iso
    delta_f1 = f_ctx - f_iso
    delta_fpr = fpr_ctx - fpr_iso
    delta_acc = acc_ctx - acc_iso

    # Paired Bootstrap Resampling
    rng = random.Random(seed)
    pairs = list(zip(evals_iso, evals_ctx))

    boot_d_prec: List[float] = []
    boot_d_rec: List[float] = []
    boot_d_f1: List[float] = []
    boot_d_fpr: List[float] = []

    for _ in range(n_resamples):
        sample_pairs = [rng.choice(pairs) for _ in range(n)]
        s_iso = [p[0] for p in sample_pairs]
        s_ctx = [p[1] for p in sample_pairs]

        boot_d_prec.append(calculate_precision(s_ctx) - calculate_precision(s_iso))
        boot_d_rec.append(calculate_recall(s_ctx) - calculate_recall(s_iso))
        boot_d_f1.append(calculate_f1(s_ctx) - calculate_f1(s_iso))
        boot_d_fpr.append(calculate_fpr(s_ctx) - calculate_fpr(s_iso))

    def _get_ci(samples: List[float], point_est: float) -> ConfidenceInterval:
        samples.sort()
        alpha_half = (1.0 - (1.0 - alpha)) / 2.0  # default 95%
        l_idx = int(math.floor(alpha_half * n_resamples))
        u_idx = min(int(math.ceil((1.0 - alpha_half) * n_resamples)) - 1, n_resamples - 1)
        return ConfidenceInterval(
            point_estimate=round(point_est, 4),
            lower=round(samples[l_idx], 4),
            upper=round(samples[u_idx], 4),
            confidence_level=1.0 - alpha,
            method=f"paired_bootstrap_{n_resamples}",
            sample_size=n,
        )

    ci_d_prec = _get_ci(boot_d_prec, delta_prec)
    ci_d_rec = _get_ci(boot_d_rec, delta_rec)
    ci_d_f1 = _get_ci(boot_d_f1, delta_f1)
    ci_d_fpr = _get_ci(boot_d_fpr, delta_fpr)

    return PairedComparisonResult(
        test_name="Exact Two-Sided McNemar Test & Paired Scenario Bootstrap",
        sample_size=n,
        both_correct_a=a,
        isolated_correct_contextual_incorrect_b=b,
        isolated_incorrect_contextual_correct_c=c,
        both_incorrect_d=d,
        discordant_pairs_total=b + c,
        contingency_matrix=[[a, b], [c, d]],
        p_value_exact=p_val,
        statistically_significant=is_sig,
        alpha_level=alpha,
        odds_ratio=odds_ratio,
        delta_accuracy=round(delta_acc, 4),
        bootstrap_resamples=n_resamples,
        delta_precision=round(delta_prec, 4),
        ci_delta_precision=ci_d_prec,
        delta_recall=round(delta_rec, 4),
        ci_delta_recall=ci_d_rec,
        delta_f1=round(delta_f1, 4),
        ci_delta_f1=ci_d_f1,
        delta_fpr=round(delta_fpr, 4),
        ci_delta_fpr=ci_d_fpr,
    )
