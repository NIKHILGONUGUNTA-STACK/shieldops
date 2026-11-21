"""Comprehensive Unit and Integration Tests for Phase 7.3.6 Research Evaluation Framework."""

import pytest

from simulation.evaluation.contextual_detector import (
    AblationConfig,
    ContextualDetector,
)
from simulation.evaluation.dataset_generator import EvaluationDatasetGenerator
from simulation.evaluation.evaluation_engine import ResearchEvaluationEngine
from simulation.evaluation.isolated_detector import IsolatedRuleDetector
from simulation.evaluation.models import (
    ClassificationOutcome,
    EvaluationUnit,
    GroundTruthCategory,
    UnitEvaluation,
)
from simulation.evaluation.statistical_metrics import (
    calculate_f1,
    calculate_fpr,
    calculate_precision,
    calculate_recall,
    compile_metric_report,
    compute_bootstrap_ci,
    compute_wilson_score_interval,
)


@pytest.fixture
def dataset_bundle():
    gen = EvaluationDatasetGenerator(master_seed=42)
    manifest, telemetry = gen.generate_dataset()
    return manifest, telemetry


def test_dataset_manifest_integrity_and_proportions(dataset_bundle):
    manifest, telemetry = dataset_bundle

    assert manifest.total_scenarios == 200
    assert manifest.benign_count == 80
    assert manifest.malicious_count == 70
    assert manifest.ambiguous_count == 30
    assert manifest.incomplete_count == 20

    # Verify deterministic hash
    expected_hash = manifest.calculate_hash()
    assert manifest.manifest_hash == expected_hash
    assert len(manifest.manifest_hash) == 64

    # Verify all 200 scenarios have corresponding telemetry
    assert len(telemetry) == 200


def test_telemetry_ground_truth_isolation(dataset_bundle):
    """Verifies that telemetry fed to detectors is completely free of ground-truth labels."""
    _, telemetry = dataset_bundle

    for sc_id, events in telemetry.items():
        for ev in events:
            # Must not contain scenario names or ground-truth expectations
            assert not hasattr(ev, "ground_truth")
            assert not hasattr(ev, "expected_detection")
            assert not hasattr(ev, "expected_rules")
            assert not hasattr(ev, "scenario_name")


def test_wilson_score_interval_bounds():
    # 0/100 -> lower=0, upper > 0
    ci_zero = compute_wilson_score_interval(0, 100)
    assert ci_zero.point_estimate == 0.0
    assert ci_zero.lower == 0.0
    assert 0.0 < ci_zero.upper < 0.05

    # 50/100 -> centered around 0.5
    ci_half = compute_wilson_score_interval(50, 100)
    assert ci_half.point_estimate == 0.5
    assert 0.40 < ci_half.lower < 0.50
    assert 0.50 < ci_half.upper < 0.60

    # 100/100 -> upper=1.0, lower < 1.0
    ci_one = compute_wilson_score_interval(100, 100)
    assert ci_one.point_estimate == 1.0
    assert 0.95 < ci_one.lower < 1.0
    assert ci_one.upper == 1.0

    # Zero denominator safety
    ci_empty = compute_wilson_score_interval(0, 0)
    assert ci_empty.point_estimate == 0.0
    assert ci_empty.sample_size == 0


def test_bootstrap_ci_reproducibility():
    evals = [
        UnitEvaluation(
            unit=EvaluationUnit.SCENARIO_LEVEL,
            unit_id=f"sc-{i}",
            ground_truth_category=GroundTruthCategory.MALICIOUS,
            expected_detection=True,
            actual_detection=True if i < 80 else False,
            is_uncertain=False,
            classification=ClassificationOutcome.TP if i < 80 else ClassificationOutcome.FN,
            triggered_rules=["RULE-BOLA-01"],
            campaign_identified=False,
            explanation="",
        )
        for i in range(100)
    ]

    ci1 = compute_bootstrap_ci(evals, calculate_recall, n_resamples=200, seed=42)
    ci2 = compute_bootstrap_ci(evals, calculate_recall, n_resamples=200, seed=42)

    assert ci1.point_estimate == 0.8
    assert ci1.lower == ci2.lower
    assert ci1.upper == ci2.upper
    assert ci1.lower <= 0.8 <= ci1.upper


def test_evaluation_engine_shows_statistically_significant_contextual_gain(dataset_bundle):
    manifest, telemetry = dataset_bundle
    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    iso = result.isolated_scenario_metrics
    ctx = result.contextual_scenario_metrics

    # Contextual F1 must be strictly superior to Isolated Rules
    assert ctx.f1_score > iso.f1_score
    assert ctx.recall == 1.0
    assert iso.recall < 0.70  # Isolated rules miss stealth, pagination, and multi-stage campaigns

    # Non-overlapping bootstrap confidence intervals on F1
    assert ctx.ci_f1 is not None and iso.ci_f1 is not None
    assert ctx.ci_f1.lower > iso.ci_f1.upper

    # Contextual correlator detects campaigns
    assert result.contextual_campaign_metrics.f1_score == 1.0
    assert result.isolated_campaign_metrics.confusion_matrix.true_positives == 0


def test_ablation_signal_contributions(dataset_bundle):
    manifest, telemetry = dataset_bundle
    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    ablations = result.ablation_results
    full_f1 = ablations["FULL_CONTEXTUAL"].f1_score

    # Disabling resource ownership severely degrades detection (drop >= 10%)
    no_own = ablations["NO_OWNERSHIP"]
    assert no_own.f1_score < full_f1
    assert no_own.recall < 0.80

    # Disabling sensitivity degrades detection
    no_sens = ablations["NO_SENSITIVITY"]
    assert no_sens.f1_score < full_f1

    # Disabling temporal memory drops F1
    no_temp = ablations["NO_TEMPORAL"]
    assert no_temp.f1_score < full_f1


def test_uncertainty_handling_evaluation(dataset_bundle):
    manifest, telemetry = dataset_bundle
    engine = ResearchEvaluationEngine(manifest, telemetry)
    result = engine.run_full_evaluation()

    unc_metrics = result.uncertainty_handling_metrics
    # Must correctly handle uncertainty on ambiguous and incomplete scenarios
    assert unc_metrics.confusion_matrix.uncertain_handled >= 25
