"""Statistical calculation engine for Phase 7.3.6.

Implements:
1. Exact confusion matrix & rate derivations with zero-denominator safety.
2. Wilson score interval for binomial proportions.
3. Non-parametric bootstrap confidence intervals (resampling at the independent scenario/campaign level).
4. Robust latency distribution statistics (Median, P95, P99).
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Callable, List, Optional, Tuple

from simulation.evaluation.models import (
    ClassificationOutcome,
    ConfidenceInterval,
    ConfusionMatrix,
    GroundTruthCategory,
    LatencyStats,
    MetricReport,
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
    # z for 95% is ~1.95996; for 99% is ~2.57583
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
    n_resamples: int = 1000,
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
    fp = sum(1 for e in evals if e.classification == ClassificationOutcome.FP)
    tn = sum(1 for e in evals if e.classification == ClassificationOutcome.TN)
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


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


def compile_metric_report(
    evaluations: List[UnitEvaluation],
    latencies_ms: Optional[List[float]] = None,
    total_duration_sec: float = 1.0,
) -> MetricReport:
    """Aggregates unit evaluations into a complete MetricReport with CIs."""
    total = len(evaluations)
    tp = sum(1 for e in evaluations if e.classification == ClassificationOutcome.TP)
    fp = sum(1 for e in evaluations if e.classification == ClassificationOutcome.FP)
    tn = sum(1 for e in evaluations if e.classification == ClassificationOutcome.TN)
    fn = sum(1 for e in evaluations if e.classification == ClassificationOutcome.FN)
    unc_handled = sum(1 for e in evaluations if e.classification == ClassificationOutcome.UNCERTAIN_CORRECT)
    unc_misclass = sum(1 for e in evaluations if e.classification == ClassificationOutcome.UNCERTAIN_INCORRECT)

    cm = ConfusionMatrix(
        total_samples=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        uncertain_handled=unc_handled,
        uncertain_misclassified=unc_misclass,
    )

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    acc = (tp + tn + unc_handled) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    unc_rate = (unc_handled + unc_misclass) / total if total > 0 else 0.0

    # CIs
    ci_p = compute_bootstrap_ci(evaluations, calculate_precision, n_resamples=500, seed=42)
    ci_r = compute_bootstrap_ci(evaluations, calculate_recall, n_resamples=500, seed=42)
    ci_f = compute_bootstrap_ci(evaluations, calculate_f1, n_resamples=500, seed=42)
    ci_fpr_val = compute_wilson_score_interval(fp, fp + tn) if (fp + tn) > 0 else None

    lat = calculate_latency_stats(latencies_ms or [])
    throughput = (total / total_duration_sec) if total_duration_sec > 0 else 0.0

    return MetricReport(
        confusion_matrix=cm,
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1_score=round(f1, 4),
        accuracy=round(acc, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        specificity=round(spec, 4),
        uncertainty_rate=round(unc_rate, 4),
        ci_precision=ci_p,
        ci_recall=ci_r,
        ci_f1=ci_f,
        ci_fpr=ci_fpr_val,
        latency=lat,
        throughput_eps=round(throughput, 2),
    )
