"""Isolated Rule-Based Detection Engine (Baseline Experiment A).

Evaluates individual API security events in complete isolation:
- No temporal sliding window.
- No cross-request state memory.
- No customer identity / JWT subject anti-affinity.
- No resource ownership claim validation.
- No multi-stage attack campaign correlation.

Operates exclusively on raw EventTelemetry without access to ground truth.
"""

from __future__ import annotations

import time
from typing import List, Tuple

from simulation.evaluation.models import (
    DetectionOutput,
    EvaluationUnit,
    EventTelemetry,
)


class IsolatedRuleDetector:
    """Evaluates telemetry events in a strict stateless vacuum."""

    def evaluate_event(self, event: EventTelemetry) -> DetectionOutput:
        """Evaluates a single HTTP event using isolated rule conditions."""
        start = time.perf_counter()
        triggered_rules: List[str] = []

        url = event.url.lower()
        status = event.status_code

        # Isolated Rule 1: Single 403 on customer or account route triggers RULE-BOLA-01
        # Flaw: Flags legitimate non-BOLA role denials (e.g. admin endpoint) because it lacks ownership context!
        if status == 403:
            if "/customers" in url or "/accounts" in url or "/security" in url:
                triggered_rules.append("RULE-BOLA-01")

        # Isolated Rule 2: Single 404 on actuator, admin, or swagger triggers RULE-PROBE-01
        # Flaw: Flags innocent user typos on /cutomers/profile or /admin/info without frequency checking!
        if status == 404:
            if "/actuator" in url or "/swagger" in url or "/admin" in url or "/cutomers" in url:
                triggered_rules.append("RULE-PROBE-01")

        # Isolated Rule 3: Single 200 on sensitive path with restricted keywords in URL triggers RULE-DATA-01
        if status == 200 and ("/internal-debug" in url or "/all" in url):
            triggered_rules.append("RULE-DATA-01")

        detected = len(triggered_rules) > 0
        latency_ms = (time.perf_counter() - start) * 1000.0

        return DetectionOutput(
            unit=EvaluationUnit.EVENT_LEVEL,
            unit_id=event.event_id,
            detected=detected,
            is_uncertain=False,  # Isolated rules have no uncertainty awareness
            triggered_rules=triggered_rules,
            campaign_identified=False,  # Isolated rules cannot identify campaigns
            risk_score=75.0 if detected else 0.0,
            confidence_score=0.85 if detected else 0.0,
            explanation=f"Isolated rules triggered: {', '.join(triggered_rules)}" if detected else "Clean isolated event",
            processing_latency_ms=round(latency_ms, 4),
        )

    def evaluate_scenario(
        self, scenario_id: str, events: List[EventTelemetry]
    ) -> Tuple[DetectionOutput, List[DetectionOutput]]:
        """Evaluates all events in a scenario independently, aggregating scenario-level outcome."""
        start = time.perf_counter()
        event_outputs: List[DetectionOutput] = []
        all_triggered_rules: set[str] = set()

        for ev in events:
            out = self.evaluate_event(ev)
            event_outputs.append(out)
            for r in out.triggered_rules:
                all_triggered_rules.add(r)

        scenario_detected = len(all_triggered_rules) > 0
        scenario_latency = (time.perf_counter() - start) * 1000.0

        scenario_output = DetectionOutput(
            unit=EvaluationUnit.SCENARIO_LEVEL,
            unit_id=scenario_id,
            detected=scenario_detected,
            is_uncertain=False,
            triggered_rules=sorted(all_triggered_rules),
            campaign_identified=False,  # Cannot correlate into a campaign
            risk_score=80.0 if scenario_detected else 0.0,
            confidence_score=0.70 if scenario_detected else 0.0,
            explanation=(
                f"Scenario alerted via isolated rules: {', '.join(sorted(all_triggered_rules))}"
                if scenario_detected
                else "No isolated rules triggered in scenario"
            ),
            processing_latency_ms=round(scenario_latency, 4),
        )

        return scenario_output, event_outputs
