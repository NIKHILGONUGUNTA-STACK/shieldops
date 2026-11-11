"""Research Evaluation Suite for Data Leakage and BOLA Detection.

Computes academic and security benchmark metrics across labelled simulation scenarios:
- Confusion Matrix: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
- Precision, Recall, F1 Score, Accuracy, False Positive Rate (FPR), and Specificity (TNR)
- Detailed per-scenario classification outcomes and markdown table generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class GroundTruthLabel(str, Enum):
    """Ground truth category of a simulation scenario."""

    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"


class ClassificationResult(str, Enum):
    """Confusion matrix category."""

    TP = "TP"  # Malicious attack correctly detected
    TN = "TN"  # Benign workflow correctly allowed without false alarm
    FP = "FP"  # Benign workflow falsely flagged as attack
    FN = "FN"  # Malicious attack missed / not detected


class ScenarioEvaluation(BaseModel):
    """Evaluation result for an individual simulation scenario."""

    scenario_id: str
    scenario_name: str
    ground_truth: GroundTruthLabel
    expected_rules: list[str] = Field(default_factory=list)
    triggered_rules: list[str] = Field(default_factory=list)
    incident_count: int = 0
    classification: ClassificationResult
    explanation: str


class EvaluationMetrics(BaseModel):
    """Comprehensive research evaluation metrics."""

    total_scenarios: int = 0
    total_benign: int = 0
    total_malicious: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0
    specificity: float = 0.0
    evaluations: list[ScenarioEvaluation] = Field(default_factory=list)

    def to_markdown_table(self) -> str:
        """Renders an academic markdown report table of the evaluation results."""
        rows = [
            "### Data Leakage Detection Research Benchmark Metrics",
            "",
            "| Metric | Value | Description |",
            "|---|---|---|",
            f"| **Total Scenarios** | `{self.total_scenarios}` | Total evaluated scenarios (Benign + Malicious) |",
            f"| **True Positives (TP)** | `{self.true_positives}` | Malicious attacks correctly flagged |",
            f"| **False Positives (FP)** | `{self.false_positives}` | Benign customer workflows falsely flagged |",
            f"| **True Negatives (TN)** | `{self.true_negatives}` | Benign workflows correctly allowed |",
            f"| **False Negatives (FN)** | `{self.false_negatives}` | Malicious attacks missed by detection |",
            f"| **Precision** | `{self.precision * 100:.2f}%` | Precision = TP / (TP + FP) |",
            f"| **Recall (Sensitivity)** | `{self.recall * 100:.2f}%` | Recall = TP / (TP + FN) |",
            f"| **F1 Score** | `{self.f1_score:.4f}` | Harmonic mean of Precision and Recall |",
            f"| **Accuracy** | `{self.accuracy * 100:.2f}%` | (TP + TN) / Total |",
            f"| **False Positive Rate** | `{self.false_positive_rate * 100:.2f}%` | FP / (FP + TN) |",
            "",
            "#### Scenario-by-Scenario Evaluation Matrix",
            "",
            "| Scenario ID | Name | Ground Truth | Detected Rules | Outcome | Classification |",
            "|---|---|---|---|---|---|",
        ]

        for ev in self.evaluations:
            rules_str = ", ".join(ev.triggered_rules) if ev.triggered_rules else "None"
            rows.append(
                f"| `{ev.scenario_id}` | {ev.scenario_name} | `{ev.ground_truth.value}` | `{rules_str}` | {ev.explanation} | **`{ev.classification.value}`** |"
            )

        return "\n".join(rows)


class BenchmarkEvaluator:
    """Evaluates scenario execution results against ground truth labels."""

    @staticmethod
    def evaluate_scenario(
        scenario_id: str,
        scenario_name: str,
        ground_truth: GroundTruthLabel,
        expected_rules: list[str],
        triggered_rules: list[str],
        incident_count: int = 0,
    ) -> ScenarioEvaluation:
        """Evaluates a single scenario run against its ground truth expectation."""
        has_detection = len(triggered_rules) > 0 or incident_count > 0

        if ground_truth == GroundTruthLabel.MALICIOUS:
            if has_detection:
                classification = ClassificationResult.TP
                explanation = f"Correctly detected ({len(triggered_rules)} rule(s) fired)"
            else:
                classification = ClassificationResult.FN
                explanation = "Attack was not detected by any rule (Missed)"
        else:
            if not has_detection:
                classification = ClassificationResult.TN
                explanation = "Clean benign run (0 false alarms)"
            else:
                classification = ClassificationResult.FP
                explanation = f"False positive alert triggered on benign traffic ({', '.join(triggered_rules)})"

        return ScenarioEvaluation(
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            ground_truth=ground_truth,
            expected_rules=expected_rules,
            triggered_rules=triggered_rules,
            incident_count=incident_count,
            classification=classification,
            explanation=explanation,
        )

    @classmethod
    def calculate_metrics(cls, evaluations: list[ScenarioEvaluation]) -> EvaluationMetrics:
        """Calculates aggregated confusion matrix and research metrics."""
        tp = sum(1 for e in evaluations if e.classification == ClassificationResult.TP)
        fp = sum(1 for e in evaluations if e.classification == ClassificationResult.FP)
        tn = sum(1 for e in evaluations if e.classification == ClassificationResult.TN)
        fn = sum(1 for e in evaluations if e.classification == ClassificationResult.FN)

        total = len(evaluations)
        total_benign = sum(1 for e in evaluations if e.ground_truth == GroundTruthLabel.BENIGN)
        total_malicious = sum(1 for e in evaluations if e.ground_truth == GroundTruthLabel.MALICIOUS)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = ((tp + tn) / total) if total > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        specificity = (tn / (tn + fp)) if (tn + fp) > 0 else 1.0

        return EvaluationMetrics(
            total_scenarios=total,
            total_benign=total_benign,
            total_malicious=total_malicious,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            false_positive_rate=fpr,
            specificity=specificity,
            evaluations=evaluations,
        )
