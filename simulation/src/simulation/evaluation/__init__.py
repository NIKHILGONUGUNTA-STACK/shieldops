"""Research evaluation package for Phase 7.3.6."""

from simulation.evaluation.contextual_detector import (
    AblationConfig,
    ContextualDetector,
)
from simulation.evaluation.dataset_generator import EvaluationDatasetGenerator
from simulation.evaluation.evaluation_engine import (
    ComparativeEvaluationResult,
    ResearchEvaluationEngine,
)
from simulation.evaluation.isolated_detector import IsolatedRuleDetector
from simulation.evaluation.models import (
    ClassificationOutcome,
    DatasetManifest,
    DetectionOutput,
    EvaluationMode,
    EvaluationUnit,
    EventTelemetry,
    GroundTruthCategory,
    MetricReport,
    ScenarioGroundTruth,
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

__all__ = [
    "AblationConfig",
    "ClassificationOutcome",
    "ComparativeEvaluationResult",
    "ContextualDetector",
    "DatasetManifest",
    "DetectionOutput",
    "EvaluationDatasetGenerator",
    "EvaluationMode",
    "EvaluationUnit",
    "EventTelemetry",
    "GroundTruthCategory",
    "IsolatedRuleDetector",
    "MetricReport",
    "ResearchEvaluationEngine",
    "ScenarioGroundTruth",
    "UnitEvaluation",
    "calculate_f1",
    "calculate_fpr",
    "calculate_precision",
    "calculate_recall",
    "compile_metric_report",
    "compute_bootstrap_ci",
    "compute_wilson_score_interval",
]
