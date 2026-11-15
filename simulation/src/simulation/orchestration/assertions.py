"""Detection assertions and verification framework for simulation campaigns."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DetectionAssertionResult(BaseModel):
    """Result of an individual expected-versus-actual assertion."""
    assertion_type: str = Field(..., description="RULE_TRIGGERED, INCIDENT_SEVERITY, CAMPAIGN_CORRELATED, POLICY_DECISION")
    expected: Any
    actual: Any
    passed: bool
    details: str = ""


class StageVerificationReport(BaseModel):
    """Verification results for an individual campaign stage."""
    stage_id: str
    scenario_id: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    assertions: List[DetectionAssertionResult] = Field(default_factory=list)
    stage_passed: bool = True
    error_messages: List[str] = Field(default_factory=list)


class CampaignVerificationSummary(BaseModel):
    """Comprehensive expected-versus-actual summary across all stages of a campaign run."""
    run_id: str
    campaign_id: str
    total_stages: int
    passed_stages: int
    failed_stages: int
    total_assertions: int
    passed_assertions: int
    failed_assertions: int
    overall_passed: bool
    stage_reports: List[StageVerificationReport] = Field(default_factory=list)
    observed_rules: List[str] = Field(default_factory=list)
    observed_incidents: List[str] = Field(default_factory=list)
    observed_campaigns: List[str] = Field(default_factory=list)
    observed_policy_actions: List[str] = Field(default_factory=list)


def evaluate_stage_assertions(
    stage_id: str,
    scenario_id: str,
    expected_rules: List[str],
    expected_severity: Optional[str],
    actual_rules: List[str],
    actual_incidents: List[Dict[str, Any]],
    actual_campaigns: List[Dict[str, Any]],
    actual_policy_decisions: List[Dict[str, Any]],
    request_count: int,
    success_count: int,
    fail_count: int,
) -> StageVerificationReport:
    """Evaluates expected-versus-actual assertions for a completed stage."""
    assertions: List[DetectionAssertionResult] = []

    # 1. Rule assertions
    if not expected_rules:
        # Expect NO security alerts for benign
        security_rules_fired = [r for r in actual_rules if not r.startswith("RULE-BENIGN")]
        passed = len(security_rules_fired) == 0
        assertions.append(DetectionAssertionResult(
            assertion_type="NO_UNEXPECTED_RULES",
            expected="[]",
            actual=str(security_rules_fired),
            passed=passed,
            details="Verified zero false positive rules fired during benign stage" if passed else f"Unexpected rules: {security_rules_fired}"
        ))
    else:
        for rule in expected_rules:
            # Check if rule was observed in actual rules or incident summaries
            matched = any(rule in r for r in actual_rules) or any(rule in inc.get("rule_id", "") for inc in actual_incidents)
            assertions.append(DetectionAssertionResult(
                assertion_type="EXPECTED_RULE_TRIGGERED",
                expected=rule,
                actual="TRIGGERED" if matched else "NOT_TRIGGERED",
                passed=matched,
                details=f"Rule {rule} was verified in detection telemetry" if matched else f"Rule {rule} failed to trigger"
            ))

    # 2. Incident severity assertion
    if expected_severity:
        severities = [inc.get("severity", "").upper() for inc in actual_incidents]
        matched_sev = expected_severity.upper() in severities
        assertions.append(DetectionAssertionResult(
            assertion_type="INCIDENT_SEVERITY_MATCH",
            expected=expected_severity.upper(),
            actual=str(severities),
            passed=matched_sev,
            details=f"Incident with severity {expected_severity} recorded" if matched_sev else f"Expected {expected_severity}, found {severities}"
        ))

    # 3. Campaign correlation assertion if expected
    if any("CAMPAIGN" in r for r in expected_rules):
        campaign_found = len(actual_campaigns) > 0
        assertions.append(DetectionAssertionResult(
            assertion_type="CAMPAIGN_CORRELATED",
            expected=True,
            actual=campaign_found,
            passed=campaign_found,
            details="Attack campaign correlated by correlation engine" if campaign_found else "No campaign correlated"
        ))

    all_passed = all(a.passed for a in assertions)

    return StageVerificationReport(
        stage_id=stage_id,
        scenario_id=scenario_id,
        total_requests=request_count,
        successful_requests=success_count,
        failed_requests=fail_count,
        assertions=assertions,
        stage_passed=all_passed,
    )

