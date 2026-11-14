"""Phase 7.2.4.6: Research Evaluation & Simulation Tests for Adaptive Security Response and Policy Decision Engine.

Validates the 14 required research evaluation scenarios:
 1. Repeated reconnaissance (MONITOR_ACTIVITY)
 2. Authorization probing (REVIEW_AUTHORIZATION)
 3. Confirmed unauthorized resource access (ESCALATE_INCIDENT)
 4. Sensitive data exposure (REVIEW_DATA_EXPOSURE)
 5. Excessive data exposure / schema drift (REVIEW_DATA_EXPOSURE)
 6. Rapid bulk extraction (INVESTIGATE_ACTIVITY)
 7. Low-and-slow extraction (INVESTIGATE_ACTIVITY)
 8. Multi-domain extraction (INVESTIGATE_ACTIVITY)
 9. Multi-stage exfiltration campaign (PRIORITIZE_CAMPAIGN)
10. Incomplete or ambiguous evidence (REQUEST_ADDITIONAL_EVIDENCE)
11. Edge cases (missing context, degraded telemetry, unclassified metadata)
12. Disabled policy handling (advisory fallback and log annotation)
13. Policy version changes and threshold audit trail retention
14. Analyst decision workflow (approval, rejection with mandatory rationale, action audit)
"""

import json
import pytest
from typing import Dict, Any, List


class PolicyAction:
    MONITOR_ACTIVITY = "MONITOR_ACTIVITY"
    INVESTIGATE_ACTIVITY = "INVESTIGATE_ACTIVITY"
    REVIEW_AUTHORIZATION = "REVIEW_AUTHORIZATION"
    REVIEW_DATA_EXPOSURE = "REVIEW_DATA_EXPOSURE"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"
    PRIORITIZE_CAMPAIGN = "PRIORITIZE_CAMPAIGN"
    REQUEST_ADDITIONAL_EVIDENCE = "REQUEST_ADDITIONAL_EVIDENCE"


class PolicyStatus:
    RECOMMENDED = "RECOMMENDED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class EvidenceCompleteness:
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    DEGRADED = "DEGRADED"


class MockPolicyDecisionEngine:
    """Python simulation model representing the ShieldOps Adaptive Policy Decision Engine."""

    def __init__(self, policies: Dict[str, Dict[str, Any]] = None):
        self.policies = policies or {
            "POL-RECON-01": {
                "id": "POL-RECON-01", "version": "1.0.0", "action": PolicyAction.MONITOR_ACTIVITY,
                "category": "RECONNAISSANCE", "risk_threshold": 20.0, "enabled": True
            },
            "POL-BOLA-PROBE-01": {
                "id": "POL-BOLA-PROBE-01", "version": "1.0.0", "action": PolicyAction.REVIEW_AUTHORIZATION,
                "category": "AUTHORIZATION", "risk_threshold": 45.0, "enabled": True
            },
            "POL-BOLA-CONFIRMED-01": {
                "id": "POL-BOLA-CONFIRMED-01", "version": "1.0.0", "action": PolicyAction.ESCALATE_INCIDENT,
                "category": "AUTHORIZATION", "risk_threshold": 85.0, "enabled": True
            },
            "POL-DATA-EXPOSURE-01": {
                "id": "POL-DATA-EXPOSURE-01", "version": "1.0.0", "action": PolicyAction.REVIEW_DATA_EXPOSURE,
                "category": "DATA_EXPOSURE", "risk_threshold": 70.0, "enabled": True
            },
            "POL-BULK-EXTRACT-01": {
                "id": "POL-BULK-EXTRACT-01", "version": "1.0.0", "action": PolicyAction.INVESTIGATE_ACTIVITY,
                "category": "BULK_EXTRACTION", "risk_threshold": 75.0, "enabled": True
            },
            "POL-LOW-SLOW-01": {
                "id": "POL-LOW-SLOW-01", "version": "1.0.0", "action": PolicyAction.INVESTIGATE_ACTIVITY,
                "category": "BULK_EXTRACTION", "risk_threshold": 65.0, "enabled": True
            },
            "POL-MULTI-DOMAIN-01": {
                "id": "POL-MULTI-DOMAIN-01", "version": "1.0.0", "action": PolicyAction.INVESTIGATE_ACTIVITY,
                "category": "BULK_EXTRACTION", "risk_threshold": 80.0, "enabled": True
            },
            "POL-CAMPAIGN-01": {
                "id": "POL-CAMPAIGN-01", "version": "1.0.0", "action": PolicyAction.PRIORITIZE_CAMPAIGN,
                "category": "CAMPAIGN", "risk_threshold": 85.0, "enabled": True
            },
            "POL-AMBIGUOUS-EVIDENCE-01": {
                "id": "POL-AMBIGUOUS-EVIDENCE-01", "version": "1.0.0", "action": PolicyAction.REQUEST_ADDITIONAL_EVIDENCE,
                "category": "EVIDENCE_INTEGRITY", "risk_threshold": 30.0, "enabled": True
            }
        }
        self.decisions: List[Dict[str, Any]] = []
        self.audit_log: List[Dict[str, Any]] = []

    def evaluate_incident(self, incident: Dict[str, Any], evidence_items: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        evidence_items = evidence_items or []

        # Check evidence completeness gate
        target_entity = incident.get("target_entity_value", "")
        rule_id = incident.get("rule_id", "")

        is_ambiguous = (
            not evidence_items or
            target_entity in ("UNKNOWN", "", None) or
            incident.get("evidence_completeness") in (EvidenceCompleteness.INCOMPLETE, EvidenceCompleteness.DEGRADED)
        )

        if is_ambiguous:
            policy_id = "POL-AMBIGUOUS-EVIDENCE-01"
            pol = self.policies[policy_id]
            decision = {
                "decision_id": f"dec-{len(self.decisions)+1}",
                "incident_id": incident.get("id"),
                "campaign_id": None,
                "policy_id": policy_id,
                "policy_version": pol["version"],
                "category": pol["category"],
                "risk_level": "MEDIUM",
                "recommended_action": pol["action"],
                "enforcement_level": "ADVISORY",
                "rationale": "Severe response suppressed due to ambiguous or degraded evidence. Forensic enrichment requested.",
                "evidence_completeness": EvidenceCompleteness.INCOMPLETE,
                "status": PolicyStatus.RECOMMENDED,
                "evidence_snapshot": json.dumps({"incident": incident, "evidence_count": len(evidence_items)})
            }
            self.decisions.append(decision)
            return decision

        # Route by incident threat type / rule
        if rule_id == "RULE-BOLA-CONFIRMED-01":
            policy_id = "POL-BOLA-CONFIRMED-01"
            risk_level = "CRITICAL"
        elif rule_id == "RULE-BOLA-02":
            policy_id = "POL-BOLA-PROBE-01"
            risk_level = "MEDIUM"
        elif rule_id in ("RULE-DATA-LEAK-01", "RULE-EXCESSIVE-EXPOSURE-01"):
            policy_id = "POL-DATA-EXPOSURE-01"
            risk_level = "HIGH"
        elif rule_id == "RULE-BULK-EXTRACT-01":
            policy_id = "POL-BULK-EXTRACT-01"
            risk_level = "HIGH"
        elif rule_id == "RULE-LOW-SLOW-01":
            policy_id = "POL-LOW-SLOW-01"
            risk_level = "MEDIUM"
        elif rule_id == "RULE-MULTI-DOMAIN-01":
            policy_id = "POL-MULTI-DOMAIN-01"
            risk_level = "HIGH"
        elif rule_id in ("RULE-RECON-01", "RULE-PROBE-01"):
            policy_id = "POL-RECON-01"
            risk_level = "LOW"
        else:
            policy_id = "POL-RECON-01"
            risk_level = "LOW"

        pol = self.policies.get(policy_id, self.policies["POL-RECON-01"])
        action = pol["action"]
        rationale = f"Evaluated incident {incident.get('id')} under policy {policy_id}."

        if not pol.get("enabled", True):
            action = PolicyAction.MONITOR_ACTIVITY
            rationale = f"[POLICY {policy_id} DISABLED] Severe action suppressed; falling back to passive monitoring."

        decision = {
            "decision_id": f"dec-{len(self.decisions)+1}",
            "incident_id": incident.get("id"),
            "campaign_id": None,
            "policy_id": policy_id,
            "policy_version": pol["version"],
            "category": pol["category"],
            "risk_level": risk_level,
            "recommended_action": action,
            "enforcement_level": "ADVISORY",
            "rationale": rationale,
            "evidence_completeness": EvidenceCompleteness.COMPLETE,
            "status": PolicyStatus.RECOMMENDED,
            "evidence_snapshot": json.dumps({"incident": incident, "evidence": evidence_items})
        }
        self.decisions.append(decision)
        return decision

    def evaluate_campaign(self, campaign: Dict[str, Any]) -> Dict[str, Any]:
        completeness = campaign.get("evidence_completeness", EvidenceCompleteness.COMPLETE)

        if completeness in (EvidenceCompleteness.INCOMPLETE, EvidenceCompleteness.DEGRADED):
            policy_id = "POL-AMBIGUOUS-EVIDENCE-01"
            pol = self.policies[policy_id]
            decision = {
                "decision_id": f"dec-{len(self.decisions)+1}",
                "incident_id": None,
                "campaign_id": campaign.get("id"),
                "policy_id": policy_id,
                "policy_version": pol["version"],
                "category": pol["category"],
                "risk_level": "MEDIUM",
                "recommended_action": pol["action"],
                "enforcement_level": "ADVISORY",
                "rationale": "Severe campaign response suppressed due to missing telemetry or unclassified metadata.",
                "evidence_completeness": completeness,
                "status": PolicyStatus.RECOMMENDED,
                "evidence_snapshot": json.dumps({"campaign": campaign})
            }
            self.decisions.append(decision)
            return decision

        policy_id = "POL-CAMPAIGN-01"
        pol = self.policies[policy_id]
        score = campaign.get("risk_score", 0.0)

        decision = {
            "decision_id": f"dec-{len(self.decisions)+1}",
            "incident_id": None,
            "campaign_id": campaign.get("id"),
            "policy_id": policy_id,
            "policy_version": pol["version"],
            "category": pol["category"],
            "risk_level": "CRITICAL" if score >= 80 else "HIGH",
            "recommended_action": pol["action"],
            "enforcement_level": "ADVISORY",
            "rationale": f"Multi-stage exfiltration campaign verified with risk score {score:.1f}.",
            "evidence_completeness": EvidenceCompleteness.COMPLETE,
            "status": PolicyStatus.RECOMMENDED,
            "evidence_snapshot": json.dumps({"campaign": campaign, "risk_score": score})
        }
        self.decisions.append(decision)
        return decision

    def update_policy(self, policy_id: str, threshold: float = None, enabled: bool = None, changed_by: str = "analyst", reason: str = ""):
        pol = self.policies[policy_id]
        prev_ver = pol["version"]
        parts = prev_ver.split(".")
        new_ver = f"{parts[0]}.{int(parts[1])+1}.0"

        if threshold is not None:
            pol["risk_threshold"] = threshold
        if enabled is not None:
            pol["enabled"] = enabled
        pol["version"] = new_ver

        self.audit_log.append({
            "policy_id": policy_id,
            "prev_version": prev_ver,
            "new_version": new_ver,
            "changed_by": changed_by,
            "reason": reason
        })

    def approve_decision(self, decision_id: str, analyst: str, comment: str) -> Dict[str, Any]:
        for d in self.decisions:
            if d["decision_id"] == decision_id:
                d["status"] = PolicyStatus.APPROVED
                d["analyst_user"] = analyst
                d["analyst_comment"] = comment
                return d
        raise ValueError(f"Decision {decision_id} not found")

    def reject_decision(self, decision_id: str, analyst: str, rationale: str) -> Dict[str, Any]:
        if not rationale or not rationale.strip():
            raise ValueError("Mandatory operational rationale required to reject policy decision.")
        for d in self.decisions:
            if d["decision_id"] == decision_id:
                d["status"] = PolicyStatus.REJECTED
                d["analyst_user"] = analyst
                d["analyst_rationale"] = rationale
                return d
        raise ValueError(f"Decision {decision_id} not found")


# ==============================================================================
# 14 Required Evaluation Scenarios
# ==============================================================================

@pytest.fixture
def engine():
    return MockPolicyDecisionEngine()


def test_scenario_01_repeated_reconnaissance(engine):
    """Scenario 1: Repeated unauthenticated reconnaissance recommends MONITOR_ACTIVITY."""
    incident = {
        "id": "inc-01", "rule_id": "RULE-RECON-01", "severity": "LOW",
        "target_entity_value": "198.51.100.20", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "404 on /actuator/env", "confidence": 0.85}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-RECON-01"
    assert decision["recommended_action"] == PolicyAction.MONITOR_ACTIVITY
    assert decision["risk_level"] == "LOW"
    assert decision["enforcement_level"] == "ADVISORY"


def test_scenario_02_authorization_probing(engine):
    """Scenario 2: Authorization probing (403 BOLA attempts) recommends REVIEW_AUTHORIZATION."""
    incident = {
        "id": "inc-02", "rule_id": "RULE-BOLA-02", "severity": "MEDIUM",
        "target_entity_value": "cust-probing-user", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "Multiple 403 Forbidden on peer accounts", "confidence": 0.90}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-BOLA-PROBE-01"
    assert decision["recommended_action"] == PolicyAction.REVIEW_AUTHORIZATION
    assert decision["risk_level"] == "MEDIUM"


def test_scenario_03_confirmed_unauthorized_access(engine):
    """Scenario 3: Confirmed unauthorized access (200 on cross-owner) recommends ESCALATE_INCIDENT."""
    incident = {
        "id": "inc-03", "rule_id": "RULE-BOLA-CONFIRMED-01", "severity": "CRITICAL",
        "target_entity_value": "cust-victim-99", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "200 OK on /api/v1/customers/cust-victim-99/profile", "confidence": 0.98}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-BOLA-CONFIRMED-01"
    assert decision["recommended_action"] == PolicyAction.ESCALATE_INCIDENT
    assert decision["risk_level"] == "CRITICAL"


def test_scenario_04_sensitive_data_exposure(engine):
    """Scenario 4: Sensitive data exposure to unauthorized party recommends REVIEW_DATA_EXPOSURE."""
    incident = {
        "id": "inc-04", "rule_id": "RULE-DATA-LEAK-01", "severity": "HIGH",
        "target_entity_value": "customer-profile", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "CONFIDENTIAL customer data returned without valid scope", "confidence": 0.92}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-DATA-EXPOSURE-01"
    assert decision["recommended_action"] == PolicyAction.REVIEW_DATA_EXPOSURE
    assert decision["risk_level"] == "HIGH"


def test_scenario_05_excessive_data_exposure_schema_drift(engine):
    """Scenario 5: Excessive exposure due to schema drift recommends REVIEW_DATA_EXPOSURE."""
    incident = {
        "id": "inc-05", "rule_id": "RULE-EXCESSIVE-EXPOSURE-01", "severity": "HIGH",
        "target_entity_value": "GET /api/v1/accounts/123", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "Undeclared RESTRICTED pin_hash field in response payload", "confidence": 0.95}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-DATA-EXPOSURE-01"
    assert decision["recommended_action"] == PolicyAction.REVIEW_DATA_EXPOSURE


def test_scenario_06_rapid_bulk_extraction(engine):
    """Scenario 6: Rapid bulk extraction recommends INVESTIGATE_ACTIVITY."""
    incident = {
        "id": "inc-06", "rule_id": "RULE-BULK-EXTRACT-01", "severity": "HIGH",
        "target_entity_value": "cust-harvester", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "15 sensitive resources retrieved in 30 seconds", "confidence": 0.94}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-BULK-EXTRACT-01"
    assert decision["recommended_action"] == PolicyAction.INVESTIGATE_ACTIVITY
    assert decision["risk_level"] == "HIGH"


def test_scenario_07_low_and_slow_extraction(engine):
    """Scenario 7: Creeping low-and-slow extraction recommends INVESTIGATE_ACTIVITY."""
    incident = {
        "id": "inc-07", "rule_id": "RULE-LOW-SLOW-01", "severity": "MEDIUM",
        "target_entity_value": "cust-subthreshold", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "8 resources retrieved at 1 req/60s across sliding window", "confidence": 0.88}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-LOW-SLOW-01"
    assert decision["recommended_action"] == PolicyAction.INVESTIGATE_ACTIVITY
    assert decision["risk_level"] == "MEDIUM"


def test_scenario_08_multi_domain_extraction(engine):
    """Scenario 8: Multi-domain cross-microservice extraction recommends INVESTIGATE_ACTIVITY."""
    incident = {
        "id": "inc-08", "rule_id": "RULE-MULTI-DOMAIN-01", "severity": "HIGH",
        "target_entity_value": "cust-attacker", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "Cross-domain access spanning Customer, Account, and Transfer", "confidence": 0.91}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["policy_id"] == "POL-MULTI-DOMAIN-01"
    assert decision["recommended_action"] == PolicyAction.INVESTIGATE_ACTIVITY


def test_scenario_09_multi_stage_campaign(engine):
    """Scenario 9: Correlated multi-stage exfiltration campaign recommends PRIORITIZE_CAMPAIGN."""
    campaign = {
        "id": "camp-01", "correlation_identity": "cust-attacker", "risk_score": 92.5,
        "stages_observed": ["RECONNAISSANCE", "AUTHORIZATION_PROBING", "BULK_EXTRACTION"],
        "evidence_completeness": EvidenceCompleteness.COMPLETE
    }

    decision = engine.evaluate_campaign(campaign)

    assert decision["policy_id"] == "POL-CAMPAIGN-01"
    assert decision["recommended_action"] == PolicyAction.PRIORITIZE_CAMPAIGN
    assert decision["risk_level"] == "CRITICAL"
    assert decision["enforcement_level"] == "ADVISORY"
    assert "92.5" in decision["evidence_snapshot"]


def test_scenario_10_incomplete_ambiguous_evidence(engine):
    """Scenario 10: Incomplete evidence suppresses severe escalation and requests forensic enrichment."""
    incident = {
        "id": "inc-10", "rule_id": "RULE-BOLA-CONFIRMED-01", "severity": "CRITICAL",
        "target_entity_value": "UNKNOWN", "evidence_completeness": EvidenceCompleteness.INCOMPLETE
    }

    decision = engine.evaluate_incident(incident, [])

    assert decision["policy_id"] == "POL-AMBIGUOUS-EVIDENCE-01"
    assert decision["recommended_action"] == PolicyAction.REQUEST_ADDITIONAL_EVIDENCE
    assert decision["risk_level"] == "MEDIUM"
    assert "Severe response suppressed" in decision["rationale"]


def test_scenario_11_edge_cases_missing_context(engine):
    """Scenario 11: Missing identity or tenant context gracefully defaults without crashing."""
    campaign = {
        "id": "camp-11", "correlation_identity": None, "risk_score": 75.0,
        "evidence_completeness": EvidenceCompleteness.DEGRADED
    }

    decision = engine.evaluate_campaign(campaign)

    assert decision["policy_id"] == "POL-AMBIGUOUS-EVIDENCE-01"
    assert decision["recommended_action"] == PolicyAction.REQUEST_ADDITIONAL_EVIDENCE
    assert decision["evidence_completeness"] == EvidenceCompleteness.DEGRADED


def test_scenario_12_disabled_policy_handling(engine):
    """Scenario 12: Disabled policy falls back to MONITOR_ACTIVITY and annotates audit rationale."""
    engine.update_policy("POL-BOLA-CONFIRMED-01", enabled=False, reason="Maintenance mode")

    incident = {
        "id": "inc-12", "rule_id": "RULE-BOLA-CONFIRMED-01", "severity": "CRITICAL",
        "target_entity_value": "cust-1", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "200 on cross-owner", "confidence": 0.95}]

    decision = engine.evaluate_incident(incident, evidence)

    assert decision["recommended_action"] == PolicyAction.MONITOR_ACTIVITY
    assert "[POLICY POL-BOLA-CONFIRMED-01 DISABLED]" in decision["rationale"]


def test_scenario_13_policy_version_and_audit_trail(engine):
    """Scenario 13: Updating policy bumps version (1.0.0 -> 1.1.0) and records audit trail."""
    engine.update_policy("POL-BULK-EXTRACT-01", threshold=80.0, changed_by="lead-analyst", reason="Tuning threshold")

    assert engine.policies["POL-BULK-EXTRACT-01"]["version"] == "1.1.0"
    assert engine.policies["POL-BULK-EXTRACT-01"]["risk_threshold"] == 80.0
    assert len(engine.audit_log) == 1
    assert engine.audit_log[0]["prev_version"] == "1.0.0"
    assert engine.audit_log[0]["new_version"] == "1.1.0"
    assert engine.audit_log[0]["reason"] == "Tuning threshold"


def test_scenario_14_analyst_decision_workflow(engine):
    """Scenario 14: Analyst can approve or reject with mandatory rationale."""
    incident = {
        "id": "inc-14", "rule_id": "RULE-BOLA-02", "severity": "MEDIUM",
        "target_entity_value": "cust-prober", "evidence_completeness": EvidenceCompleteness.COMPLETE
    }
    evidence = [{"trigger": "403 on cross-owner", "confidence": 0.90}]
    dec = engine.evaluate_incident(incident, evidence)
    dec_id = dec["decision_id"]

    # Rejection without rationale must fail
    with pytest.raises(ValueError, match="Mandatory operational rationale required"):
        engine.reject_decision(dec_id, "analyst-1", "")

    # Rejection with valid rationale succeeds
    rejected = engine.reject_decision(dec_id, "analyst-1", "Authorized penetration test by security team.")
    assert rejected["status"] == PolicyStatus.REJECTED
    assert rejected["analyst_rationale"] == "Authorized penetration test by security team."

    # Test approval on a new decision
    dec2 = engine.evaluate_incident(incident, evidence)
    approved = engine.approve_decision(dec2["decision_id"], "analyst-2", "Confirmed anomaly, following up.")
    assert approved["status"] == PolicyStatus.APPROVED
    assert approved["analyst_comment"] == "Confirmed anomaly, following up."
