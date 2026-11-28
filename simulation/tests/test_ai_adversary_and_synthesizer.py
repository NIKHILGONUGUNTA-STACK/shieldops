"""
Tests for Phase 8.2: Automated AI Adversary & Self-Healing Policy Synthesizer.
Validates the closed-loop Red Team mutation engine (step skipping, token swapping, out-of-order traversal),
candidate policy synthesis, shadow-mode zero-false-positive evaluation, and runtime hot-load healing.
"""

import re
import uuid
import time
from typing import Dict, List, Set, Any, Optional


class MockWorkflowEngine:
    """Simulation model of Gateway Workflow State Engine."""

    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.session_steps: Dict[str, Set[str]] = {}
        # Default seed rule
        self.add_rule(
            "RULE-WF-TRANSFER-01",
            "POST",
            r"^/(api/v1/)?(transactions|transfers)(/.*)?$",
            ["GET /api/v1/accounts", "GET /api/v1/customers/{id}", "GET /accounts"],
            "Payment transfer requires prior account check."
        )

    def add_rule(self, rule_id: str, method: str, path_pattern: str, required_predecessors: List[str], desc: str):
        self.rules[rule_id] = {
            "id": rule_id,
            "method": method.upper(),
            "pattern": re.compile(path_pattern),
            "predecessors": required_predecessors,
            "description": desc
        }

    def record_step(self, session_id: str, endpoint: str):
        if session_id not in self.session_steps:
            self.session_steps[session_id] = set()
        self.session_steps[session_id].add(endpoint)

    def evaluate(self, session_id: str, method: str, path: str) -> Dict[str, Any]:
        completed = self.session_steps.get(session_id, set())

        for rule in self.rules.values():
            if rule["method"] == method.upper() and rule["pattern"].match(path):
                # Check prerequisites
                satisfied = any(req in completed for req in rule["predecessors"])
                if not satisfied:
                    return {
                        "allowed": False,
                        "ruleId": rule["id"],
                        "reason": f"Workflow violation: requires prerequisite in {rule['predecessors']}"
                    }
        return {"allowed": True, "ruleId": None, "reason": None}


class AdversaryMutationEngine:
    """Autonomous Red Team adversarial sequence generator."""

    def __init__(self, engine: MockWorkflowEngine):
        self.engine = engine

    def run_campaign(self, target_endpoint: str, strategy: str, probe_count: int = 10) -> Dict[str, Any]:
        parts = target_endpoint.split(" ", 1)
        method = parts[0]
        path = parts[1]

        blocked = 0
        evaded = 0
        evasion_traces = []

        for i in range(probe_count):
            sess_id = f"sess-redteam-{uuid.uuid4().hex[:8]}"

            if strategy == "STEP_SKIPPING":
                # Red team directly calls the sensitive mutation without prerequisite
                pass
            elif strategy == "OUT_OF_ORDER_TRAVERSAL":
                # Injects wrong or arbitrary unrelated step
                self.engine.record_step(sess_id, "GET /api/v1/public/ping")
            elif strategy == "PARAMETER_TAMPERING":
                path = f"{path}?id=TAMPERED_ID_9999"

            check = self.engine.evaluate(sess_id, method, path)
            if check["allowed"]:
                evaded += 1
                evasion_traces.append({
                    "probeId": f"PRB-{i}",
                    "method": method,
                    "path": path,
                    "strategy": strategy,
                    "detail": f"Target bypassed workflow guard under {strategy}"
                })
            else:
                blocked += 1

        evasion_rate = evaded / probe_count if probe_count > 0 else 0.0
        return {
            "campaignId": f"ADV-CAMP-{uuid.uuid4().hex[:6].upper()}",
            "target": target_endpoint,
            "strategy": strategy,
            "totalProbes": probe_count,
            "blockedProbes": blocked,
            "evadedProbes": evaded,
            "evasionRate": evasion_rate,
            "evasionTraces": evasion_traces
        }


class SelfHealingPolicySynthesizer:
    """Autonomous Blue Team Policy Synthesizer with shadow-mode zero-FP safety evaluation."""

    def __init__(self, engine: MockWorkflowEngine):
        self.engine = engine
        self.candidates: Dict[str, Dict[str, Any]] = {}

    def synthesize_policy(self, campaign_result: Dict[str, Any]) -> Dict[str, Any]:
        target = campaign_result["target"]
        method, path = target.split(" ", 1)

        # Synthesize path pattern and inferred prerequisites
        base_resource = path.strip("/").split("/")[-1]
        pattern = rf"^/(api/v1/)?{base_resource}(/.*)?$"
        inferred_predecessors = ["GET /api/v1/accounts", "GET /api/v1/customers/{id}"]

        candidate_id = f"CAND-POL-{uuid.uuid4().hex[:6].upper()}"
        rule_id = f"RULE-WF-SYNTH-{uuid.uuid4().hex[:4].upper()}"

        candidate = {
            "id": candidate_id,
            "ruleId": rule_id,
            "targetMethod": method,
            "targetPathPattern": pattern,
            "requiredPredecessors": inferred_predecessors,
            "confidenceScore": 0.95,
            "shadowEvaluationsCount": 0,
            "shadowFalsePositives": 0,
            "shadowFpr": 0.0,
            "status": "CANDIDATE"
        }
        self.candidates[candidate_id] = candidate
        return candidate

    def evaluate_shadow_mode(self, candidate_id: str, batch_size: int = 50) -> Dict[str, Any]:
        candidate = self.candidates[candidate_id]
        false_positives = 0

        # Simulate benign workday journeys (benign users always query account before mutations)
        for i in range(batch_size):
            benign_history = {"GET /api/v1/accounts"}
            satisfied = any(req in benign_history for req in candidate["requiredPredecessors"])
            if not satisfied:
                false_positives += 1

        fpr = false_positives / batch_size
        candidate["shadowEvaluationsCount"] = batch_size
        candidate["shadowFalsePositives"] = false_positives
        candidate["shadowFpr"] = fpr
        candidate["status"] = "SAFE_FOR_PROMOTION" if fpr == 0.0 else "REQUIRES_TUNING"
        return candidate

    def promote_candidate(self, candidate_id: str) -> bool:
        candidate = self.candidates[candidate_id]
        if candidate["shadowFpr"] > 0.05:
            return False

        # Hot-load into live workflow engine
        self.engine.add_rule(
            candidate["ruleId"],
            candidate["targetMethod"],
            candidate["targetPathPattern"],
            candidate["requiredPredecessors"],
            f"Synthesized invariant for {candidate['targetMethod']} {candidate['targetPathPattern']}"
        )
        candidate["status"] = "PROMOTED"
        return True


# ============================================================================
# Pytest Test Suite
# ============================================================================

def test_adversary_mutation_strategies():
    engine = MockWorkflowEngine()
    red_team = AdversaryMutationEngine(engine)

    # 1. Probe protected route (POST /api/v1/transfers) -> 100% blocked
    result_transfers = red_team.run_campaign("POST /api/v1/transfers", "STEP_SKIPPING", 10)
    assert result_transfers["blockedProbes"] == 10
    assert result_transfers["evadedProbes"] == 0
    assert result_transfers["evasionRate"] == 0.0

    # 2. Probe unconstrained route (POST /api/v1/beneficiaries) -> Evasion detected
    result_beneficiaries = red_team.run_campaign("POST /api/v1/beneficiaries", "OUT_OF_ORDER_TRAVERSAL", 10)
    assert result_beneficiaries["evadedProbes"] == 10
    assert result_beneficiaries["evasionRate"] == 1.0
    assert len(result_beneficiaries["evasionTraces"]) > 0


def test_self_healing_synthesis_and_shadow_validation():
    engine = MockWorkflowEngine()
    red_team = AdversaryMutationEngine(engine)
    synthesizer = SelfHealingPolicySynthesizer(engine)

    # Step 1: Red team campaign detects policy gap on POST /api/v1/beneficiaries
    gap_campaign = red_team.run_campaign("POST /api/v1/beneficiaries", "STEP_SKIPPING", 10)
    assert gap_campaign["evasionRate"] == 1.0

    # Step 2: Synthesizer analyzes gap and drafts candidate policy
    candidate = synthesizer.synthesize_policy(gap_campaign)
    assert candidate["targetMethod"] == "POST"
    assert "GET /api/v1/accounts" in candidate["requiredPredecessors"]
    assert candidate["status"] == "CANDIDATE"

    # Step 3: Run shadow-mode evaluation against benign traffic
    evaluated = synthesizer.evaluate_shadow_mode(candidate["id"], batch_size=30)
    assert evaluated["shadowEvaluationsCount"] == 30
    assert evaluated["shadowFalsePositives"] == 0
    assert evaluated["shadowFpr"] == 0.0
    assert evaluated["status"] == "SAFE_FOR_PROMOTION"


def test_runtime_hotload_healing_blocks_subsequent_attacks():
    engine = MockWorkflowEngine()
    red_team = AdversaryMutationEngine(engine)
    synthesizer = SelfHealingPolicySynthesizer(engine)

    # Initial campaign reveals 100% evasion on unconstrained route
    initial_camp = red_team.run_campaign("POST /api/v1/beneficiaries", "STEP_SKIPPING", 10)
    assert initial_camp["evasionRate"] == 1.0

    # Synthesize and evaluate
    candidate = synthesizer.synthesize_policy(initial_camp)
    synthesizer.evaluate_shadow_mode(candidate["id"], 20)

    # Promote to active edge
    promoted = synthesizer.promote_candidate(candidate["id"])
    assert promoted is True

    # Re-run identical adversarial campaign against the healed endpoint
    healed_camp = red_team.run_campaign("POST /api/v1/beneficiaries", "STEP_SKIPPING", 10)
    assert healed_camp["blockedProbes"] == 10
    assert healed_camp["evadedProbes"] == 0
    assert healed_camp["evasionRate"] == 0.0  # Completely healed!

    # Legitimate customer with prior account check is still PERMITTED
    legit_sess = "sess-legitimate-customer-01"
    engine.record_step(legit_sess, "GET /api/v1/accounts")
    legit_check = engine.evaluate(legit_sess, "POST", "/api/v1/beneficiaries")
    assert legit_check["allowed"] is True
