"""Comprehensive Research Evaluation Engine for Phase 7.3.6.1.

Coordinates:
- Identical raw telemetry replay to both Isolated Rules and Contextual Detection.
- Strict two-population evaluation:
  1. Primary binary population (n=150: 80 Benign, 70 Malicious).
  2. Secondary ambiguous/incomplete population (n=50: 30 Ambiguous, 20 Incomplete).
- Reconciled 200/200 scenario full-population accounting and binary evaluation coverage.
- Exact two-sided McNemar test on paired scenario outcomes with Edwards continuity correction.
- Paired scenario-level bootstrap (B=2000 resamples) for metric deltas with 95% CIs.
- Explicit distinction between True FPR (FP / (FP + TN)) and FDR (FP / (TP + FP)).
- Controlled ablation suite across 8 configurations with non-mutating status evaluations.
- Dynamically executed robustness test suite.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from simulation.evaluation.contextual_detector import (
    AblationConfig,
    ContextualDetector,
)
from simulation.evaluation.isolated_detector import IsolatedRuleDetector
from simulation.evaluation.models import (
    ClassificationOutcome,
    DatasetManifest,
    DetectionOutput,
    EvaluationMode,
    EvaluationUnit,
    EventTelemetry,
    GroundTruthArtifact,
    GroundTruthCategory,
    MetricReport,
    PairedComparisonResult,
    PopulationAccounting,
    ScenarioGroundTruth,
    UncertaintyReport,
    UnitEvaluation,
)
from simulation.evaluation.statistical_metrics import (
    compile_metric_report,
    compile_population_accounting,
    compile_uncertainty_report,
    compute_paired_comparison,
)


class ComparativeEvaluationResult(BaseModel):
    """Full research evaluation comparing Isolated Rules vs Contextual Detection."""

    dataset_id: str
    dataset_version: str
    manifest_hash: str
    total_scenarios: int = 200
    benign_count: int = 80
    malicious_count: int = 70
    ambiguous_count: int = 30
    incomplete_count: int = 20

    population_accounting: PopulationAccounting

    # Primary Binary Evaluation (n=150)
    isolated_scenario_metrics: MetricReport
    contextual_scenario_metrics: MetricReport
    paired_scenario_comparison: PairedComparisonResult

    # Secondary Ambiguous/Incomplete Evaluation (n=50)
    isolated_uncertainty_metrics: UncertaintyReport
    contextual_uncertainty_metrics: UncertaintyReport

    # Event-Level Evaluation
    isolated_event_metrics: MetricReport
    contextual_event_metrics: MetricReport

    # Campaign-Level Evaluation
    isolated_campaign_metrics: MetricReport
    contextual_campaign_metrics: MetricReport

    # Backward compatibility
    uncertainty_handling_metrics: Optional[MetricReport] = None

    ablation_results: Dict[str, MetricReport] = Field(default_factory=dict)
    robustness_results: List[Dict[str, Any]] = Field(default_factory=list)
    executed_at: str = ""


class ResearchEvaluationEngine:
    """Executes dual-mode evaluations and ablations on versioned datasets."""

    def __init__(
        self,
        manifest: DatasetManifest,
        telemetry_map: Dict[str, List[EventTelemetry]],
        ground_truth: Optional[GroundTruthArtifact] = None,
    ) -> None:
        self.manifest = manifest
        self.telemetry_map = telemetry_map

        if ground_truth is not None:
            self.ground_truth = ground_truth
            self.truth_map: Dict[str, ScenarioGroundTruth] = {
                s.scenario_id: s for s in ground_truth.scenarios
            }
        elif manifest.scenarios:
            # Fallback for v1.0 where scenarios were embedded
            self.truth_map = {s.scenario_id: s for s in manifest.scenarios}
            self.ground_truth = GroundTruthArtifact(
                dataset_id=manifest.dataset_id,
                version=manifest.version,
                created_at=manifest.created_at,
                ground_truth_hash=manifest.ground_truth_hash or manifest.calculate_ground_truth_hash(),
                total_scenarios=len(manifest.scenarios),
                population_distribution={
                    "BENIGN": manifest.benign_count,
                    "MALICIOUS": manifest.malicious_count,
                    "AMBIGUOUS": manifest.ambiguous_count,
                    "INCOMPLETE_EVIDENCE": manifest.incomplete_count,
                },
                scenarios=manifest.scenarios,
            )
        else:
            raise ValueError("No ground truth provided or embedded in manifest!")

    def run_full_evaluation(self) -> ComparativeEvaluationResult:
        """Executes full comparative evaluation across all units, populations, and ablations."""
        start_time = time.time()

        isolated_detector = IsolatedRuleDetector()
        contextual_detector = ContextualDetector()

        # Track outputs for Primary Binary Population (n=150)
        iso_binary_evals: List[UnitEvaluation] = []
        ctx_binary_evals: List[UnitEvaluation] = []
        iso_binary_latencies: List[float] = []
        ctx_binary_latencies: List[float] = []

        # Track outputs for Secondary Ambiguous/Incomplete Population (n=50)
        iso_uncertainty_evals: List[UnitEvaluation] = []
        ctx_uncertainty_evals: List[UnitEvaluation] = []

        # Track outputs for Event-level
        iso_event_evals: List[UnitEvaluation] = []
        ctx_event_evals: List[UnitEvaluation] = []
        iso_event_latencies: List[float] = []
        ctx_event_latencies: List[float] = []

        # Track outputs for Campaign-level
        iso_campaign_evals: List[UnitEvaluation] = []
        ctx_campaign_evals: List[UnitEvaluation] = []

        total_iso_time = 0.0
        total_ctx_time = 0.0

        # Execute detectors across all 200 scenarios
        for sc_meta in self.ground_truth.scenarios:
            sc_id = sc_meta.scenario_id
            events = self.telemetry_map.get(sc_id, [])

            # Run Isolated Detector (strictly raw telemetry input)
            t0 = time.perf_counter()
            iso_sc_out, iso_ev_outs = isolated_detector.evaluate_scenario(sc_id, events)
            iso_time = time.perf_counter() - t0
            total_iso_time += iso_time

            # Run Contextual Detector (strictly raw telemetry input)
            t1 = time.perf_counter()
            ctx_sc_out, ctx_ev_outs = contextual_detector.evaluate_scenario(sc_id, events)
            ctx_time = time.perf_counter() - t1
            total_ctx_time += ctx_time

            is_binary = sc_meta.category in (GroundTruthCategory.BENIGN, GroundTruthCategory.MALICIOUS)

            if is_binary:
                # Primary Binary Population Evaluation (n=150)
                iso_binary_latencies.append(iso_sc_out.processing_latency_ms)
                ctx_binary_latencies.append(ctx_sc_out.processing_latency_ms)

                iso_sc_eval = self._evaluate_binary_scenario(sc_meta, iso_sc_out)
                ctx_sc_eval = self._evaluate_binary_scenario(sc_meta, ctx_sc_out)

                iso_binary_evals.append(iso_sc_eval)
                ctx_binary_evals.append(ctx_sc_eval)
            else:
                # Secondary Ambiguous / Incomplete Population Evaluation (n=50)
                iso_unc_eval = self._evaluate_uncertainty_scenario(sc_meta, iso_sc_out)
                ctx_unc_eval = self._evaluate_uncertainty_scenario(sc_meta, ctx_sc_out)

                iso_uncertainty_evals.append(iso_unc_eval)
                ctx_uncertainty_evals.append(ctx_unc_eval)

            # Event-Level Evaluation (across binary scenarios)
            if is_binary:
                for ev, iso_out, ctx_out in zip(events, iso_ev_outs, ctx_ev_outs):
                    iso_event_latencies.append(iso_out.processing_latency_ms)
                    ctx_event_latencies.append(ctx_out.processing_latency_ms)

                    # Behavioral event ground truth
                    is_cross_owner = bool(ev.resource_owner_id and ev.customer_id and ev.resource_owner_id != ev.customer_id)
                    restricted_keys = {"auth_token_hash", "temporary_cleartext_secret", "master_key"}
                    has_restricted = bool(ev.sensitivity == "RESTRICTED" or any(f in restricted_keys for f in ev.observed_fields))

                    is_malicious_event = (
                        sc_meta.category == GroundTruthCategory.MALICIOUS
                        and (ev.status_code == 403 or is_cross_owner or has_restricted)
                    )

                    iso_ev_eval = self._evaluate_event_outcome(is_malicious_event, iso_out)
                    ctx_ev_eval = self._evaluate_event_outcome(is_malicious_event, ctx_out)
                    iso_event_evals.append(iso_ev_eval)
                    ctx_event_evals.append(ctx_ev_eval)

            # Campaign-Level Evaluation (for multi-stage campaigns)
            if sc_meta.expected_campaign or "CAMPAIGN" in sc_meta.scenario_family:
                iso_camp_eval = UnitEvaluation(
                    unit=EvaluationUnit.CAMPAIGN_LEVEL,
                    unit_id=sc_id,
                    ground_truth_category=sc_meta.category,
                    expected_detection=sc_meta.expected_campaign,
                    actual_detection=iso_sc_out.campaign_identified,
                    is_uncertain=False,
                    classification=(
                        ClassificationOutcome.TP if iso_sc_out.campaign_identified and sc_meta.expected_campaign
                        else (ClassificationOutcome.FN if sc_meta.expected_campaign and not iso_sc_out.campaign_identified else ClassificationOutcome.TN)
                    ),
                    triggered_rules=iso_sc_out.triggered_rules,
                    campaign_identified=iso_sc_out.campaign_identified,
                    explanation="Isolated rules cannot correlate multi-stage campaigns",
                )
                ctx_camp_eval = UnitEvaluation(
                    unit=EvaluationUnit.CAMPAIGN_LEVEL,
                    unit_id=sc_id,
                    ground_truth_category=sc_meta.category,
                    expected_detection=sc_meta.expected_campaign,
                    actual_detection=ctx_sc_out.campaign_identified,
                    is_uncertain=False,
                    classification=(
                        ClassificationOutcome.TP if ctx_sc_out.campaign_identified and sc_meta.expected_campaign
                        else (ClassificationOutcome.FN if sc_meta.expected_campaign and not ctx_sc_out.campaign_identified else ClassificationOutcome.TN)
                    ),
                    triggered_rules=ctx_sc_out.triggered_rules,
                    campaign_identified=ctx_sc_out.campaign_identified,
                    explanation="Contextual correlator identifies multi-stage campaigns",
                )
                iso_campaign_evals.append(iso_camp_eval)
                ctx_campaign_evals.append(ctx_camp_eval)

        # 1. Primary Binary Metric Reports (n=150)
        iso_sc_metrics = compile_metric_report(iso_binary_evals, iso_binary_latencies, total_iso_time)
        ctx_sc_metrics = compile_metric_report(ctx_binary_evals, ctx_binary_latencies, total_ctx_time)

        # 2. Paired Comparative Statistical Significance Testing (Exact McNemar & Bootstrap)
        paired_comparison = compute_paired_comparison(
            iso_binary_evals,
            ctx_binary_evals,
            n_resamples=2000,
            seed=42,
            alpha=0.05,
        )

        # 3. Secondary Uncertainty & Disposition Reports (n=50)
        iso_unc_report = compile_uncertainty_report(iso_uncertainty_evals, total_ambiguous=30, total_incomplete=20)
        ctx_unc_report = compile_uncertainty_report(ctx_uncertainty_evals, total_ambiguous=30, total_incomplete=20)

        # 4. Full-Population Accounting (Reconciling 150 binary + 50 ambiguous/incomplete = 200 total)
        population_accounting = compile_population_accounting(
            total_dataset_size=200,
            binary_count=len(iso_binary_evals),
            benign_count=self.manifest.benign_count,
            malicious_count=self.manifest.malicious_count,
            ambiguous_count=self.manifest.ambiguous_count,
            incomplete_count=self.manifest.incomplete_count,
        )

        # 5. Event & Campaign Metrics
        iso_ev_metrics = compile_metric_report(iso_event_evals, iso_event_latencies, total_iso_time)
        ctx_ev_metrics = compile_metric_report(ctx_event_evals, ctx_event_latencies, total_ctx_time)

        iso_camp_metrics = compile_metric_report(iso_campaign_evals, iso_binary_latencies, total_iso_time)
        ctx_camp_metrics = compile_metric_report(ctx_campaign_evals, ctx_binary_latencies, total_ctx_time)

        # 6. Controlled Ablation Studies on Primary Binary Population
        ablation_metrics = self._run_ablation_suite()

        # 7. Dynamic Executable Robustness Test Suite
        robustness_findings = self._run_dynamic_robustness_suite()

        return ComparativeEvaluationResult(
            dataset_id=self.manifest.dataset_id,
            dataset_version=self.manifest.version,
            manifest_hash=self.manifest.manifest_hash,
            total_scenarios=self.manifest.total_scenarios,
            benign_count=self.manifest.benign_count,
            malicious_count=self.manifest.malicious_count,
            ambiguous_count=self.manifest.ambiguous_count,
            incomplete_count=self.manifest.incomplete_count,
            population_accounting=population_accounting,
            isolated_scenario_metrics=iso_sc_metrics,
            contextual_scenario_metrics=ctx_sc_metrics,
            paired_scenario_comparison=paired_comparison,
            isolated_uncertainty_metrics=iso_unc_report,
            contextual_uncertainty_metrics=ctx_unc_report,
            isolated_event_metrics=iso_ev_metrics,
            contextual_event_metrics=ctx_ev_metrics,
            isolated_campaign_metrics=iso_camp_metrics,
            contextual_campaign_metrics=ctx_camp_metrics,
            ablation_results=ablation_metrics,
            robustness_results=robustness_findings,
            executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def _evaluate_binary_scenario(
        self, meta: ScenarioGroundTruth, out: DetectionOutput
    ) -> UnitEvaluation:
        """Evaluates a scenario from the primary binary population (TP, FP, TN, FN)."""
        act = out.detected
        exp = meta.expected_detection

        if meta.category == GroundTruthCategory.MALICIOUS:
            classification = ClassificationOutcome.TP if act else ClassificationOutcome.FN
        elif meta.category == GroundTruthCategory.BENIGN:
            classification = ClassificationOutcome.FP if act else ClassificationOutcome.TN
        else:
            raise ValueError(f"Non-binary category {meta.category} passed to binary evaluation!")

        return UnitEvaluation(
            unit=EvaluationUnit.SCENARIO_LEVEL,
            unit_id=meta.scenario_id,
            ground_truth_category=meta.category,
            expected_detection=exp,
            actual_detection=act,
            is_uncertain=out.is_uncertain,
            classification=classification,
            triggered_rules=out.triggered_rules,
            campaign_identified=out.campaign_identified,
            explanation=out.explanation,
        )

    def _evaluate_uncertainty_scenario(
        self, meta: ScenarioGroundTruth, out: DetectionOutput
    ) -> UnitEvaluation:
        """Evaluates a scenario from the ambiguous/incomplete population with explicit disposition."""
        act = out.detected
        is_unc = out.is_uncertain

        if is_unc:
            cls = ClassificationOutcome.UNCERTAIN_CORRECT
        elif act:
            cls = ClassificationOutcome.FP  # Over-escalated as confident malicious attack
        else:
            cls = ClassificationOutcome.UNCERTAIN_INCORRECT  # Under-investigated / silently passed

        return UnitEvaluation(
            unit=EvaluationUnit.UNCERTAINTY_HANDLING,
            unit_id=meta.scenario_id,
            ground_truth_category=meta.category,
            expected_detection=False,
            actual_detection=act,
            is_uncertain=is_unc,
            classification=cls,
            triggered_rules=out.triggered_rules,
            campaign_identified=out.campaign_identified,
            explanation=out.explanation,
        )

    def _evaluate_event_outcome(
        self, is_malicious: bool, out: DetectionOutput
    ) -> UnitEvaluation:
        act = out.detected
        if is_malicious:
            classification = ClassificationOutcome.TP if act else ClassificationOutcome.FN
        else:
            classification = ClassificationOutcome.FP if act else ClassificationOutcome.TN

        return UnitEvaluation(
            unit=EvaluationUnit.EVENT_LEVEL,
            unit_id=out.unit_id,
            ground_truth_category=GroundTruthCategory.MALICIOUS if is_malicious else GroundTruthCategory.BENIGN,
            expected_detection=is_malicious,
            actual_detection=act,
            is_uncertain=out.is_uncertain,
            classification=classification,
            triggered_rules=out.triggered_rules,
            campaign_identified=out.campaign_identified,
            explanation=out.explanation,
        )

    def _run_ablation_suite(self) -> Dict[str, MetricReport]:
        """Runs the 8 controlled ablation configurations across the 150 primary binary scenarios."""
        configs = {
            "FULL_CONTEXTUAL": AblationConfig(),
            "NO_IDENTITY": AblationConfig(disable_identity=True),
            "NO_TENANT": AblationConfig(disable_tenant=True),
            "NO_OWNERSHIP": AblationConfig(disable_ownership=True),
            "NO_SENSITIVITY": AblationConfig(disable_sensitivity=True),
            "NO_AUTH_OUTCOME": AblationConfig(disable_auth_outcome=True),
            "NO_TEMPORAL": AblationConfig(disable_temporal=True),
            "NO_CAMPAIGN": AblationConfig(disable_campaign=True),
        }

        # Filter binary scenarios
        binary_scenarios = [
            s for s in self.ground_truth.scenarios
            if s.category in (GroundTruthCategory.BENIGN, GroundTruthCategory.MALICIOUS)
        ]

        results: Dict[str, MetricReport] = {}
        for name, cfg in configs.items():
            detector = ContextualDetector(ablation=cfg)
            evals: List[UnitEvaluation] = []
            latencies: List[float] = []

            for sc_meta in binary_scenarios:
                events = self.telemetry_map.get(sc_meta.scenario_id, [])
                sc_out, _ = detector.evaluate_scenario(sc_meta.scenario_id, events)
                latencies.append(sc_out.processing_latency_ms)
                evals.append(self._evaluate_binary_scenario(sc_meta, sc_out))

            report = compile_metric_report(evals, latencies, total_duration_sec=1.0)
            results[name] = report

        return results

    def _run_dynamic_robustness_suite(self) -> List[Dict[str, Any]]:
        """Dynamically invokes detectors to evaluate robustness edge cases across 7 functional categories."""
        detector = ContextualDetector()
        findings: List[Dict[str, Any]] = []

        # 1. Shared-IP NAT Disambiguation
        nat_events = [
            EventTelemetry(
                event_id="evt-nat-1",
                scenario_id="scen-test-nat",
                timestamp_epoch_ms=1000,
                http_method="GET",
                url="/api/v1/customers/cust_101",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_101",
                auth_subject="usr_101",
                tenant_id="tenant_1",
                source_ip="203.0.113.50",
                customer_id="cust_101",
                resource_owner_id="cust_101",
                sensitivity="CONFIDENTIAL",
                response_bytes=350,
            ),
            EventTelemetry(
                event_id="evt-nat-2",
                scenario_id="scen-test-nat",
                timestamp_epoch_ms=1500,
                http_method="GET",
                url="/api/v1/customers/cust_102",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_102",
                auth_subject="usr_102",
                tenant_id="tenant_1",
                source_ip="203.0.113.50",
                customer_id="cust_102",
                resource_owner_id="cust_102",
                sensitivity="CONFIDENTIAL",
                response_bytes=350,
            ),
        ]
        out_nat, _ = detector.evaluate_scenario("scen-test-nat", nat_events)
        passed_nat = (not out_nat.detected and not out_nat.is_uncertain)
        findings.append({
            "test_case": "Shared-IP NAT Disambiguation",
            "category": "Identity & Network",
            "expected_behavior": "Distinct customers on shared NAT (203.0.113.50) partitioned without false alarm",
            "observed_behavior": f"Detected={out_nat.detected}, Rules={out_nat.triggered_rules}",
            "passed": passed_nat,
            "dimension": "Anti-Affinity Invariant",
        })

        # 2. Cross-Owner Account Detail Probe
        probe_events = [
            EventTelemetry(
                event_id="evt-prb-1",
                scenario_id="scen-test-prb",
                timestamp_epoch_ms=2000,
                http_method="GET",
                url="/api/v1/accounts/acc_999",
                normalized_route="/api/v1/accounts/{id}",
                status_code=403,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_vic",
                sensitivity="CONFIDENTIAL",
                response_bytes=130,
            )
        ]
        out_prb, _ = detector.evaluate_scenario("scen-test-prb", probe_events)
        passed_prb = ("RULE-BOLA-01" in out_prb.triggered_rules)
        findings.append({
            "test_case": "Cross-Owner Account Detail Probe",
            "category": "Resource Ownership",
            "expected_behavior": "Mismatched resource_owner_id correctly triggers RULE-BOLA-01",
            "observed_behavior": f"Detected={out_prb.detected}, Rules={out_prb.triggered_rules}",
            "passed": passed_prb,
            "dimension": "Ownership Claim Validation",
        })

        # 3. Restricted Secret Exposure in Response
        sec_events = [
            EventTelemetry(
                event_id="evt-sec-1",
                scenario_id="scen-test-sec",
                timestamp_epoch_ms=3000,
                http_method="GET",
                url="/api/v1/customers/cust_att",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_att",
                sensitivity="RESTRICTED",
                observed_fields=["id", "auth_token_hash", "master_key"],
                response_bytes=890,
            )
        ]
        out_sec, _ = detector.evaluate_scenario("scen-test-sec", sec_events)
        passed_sec = ("RULE-EXCESSIVE-EXPOSURE-01" in out_sec.triggered_rules)
        findings.append({
            "test_case": "Restricted Secret Exposure in Response",
            "category": "Sensitivity Classification",
            "expected_behavior": "Leaking auth_token_hash triggers RULE-EXCESSIVE-EXPOSURE-01",
            "observed_behavior": f"Detected={out_sec.detected}, Rules={out_sec.triggered_rules}",
            "passed": passed_sec,
            "dimension": "Field-Level Classification",
        })

        # 4. Sliding-Window Temporal Eviction (120s)
        time_events = [
            EventTelemetry(
                event_id="evt-tm-1",
                scenario_id="scen-test-tm",
                timestamp_epoch_ms=10000,
                http_method="GET",
                url="/api/v1/customers/cust_vic1",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_vic1",
                sensitivity="CONFIDENTIAL",
                response_bytes=500,
            ),
            EventTelemetry(
                event_id="evt-tm-2",
                scenario_id="scen-test-tm",
                timestamp_epoch_ms=150000,  # 140s later (>120s)
                http_method="GET",
                url="/api/v1/customers/cust_vic2",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_vic2",
                sensitivity="CONFIDENTIAL",
                response_bytes=500,
            ),
        ]
        out_tm, _ = detector.evaluate_scenario("scen-test-tm", time_events)
        # 2 events spaced 140s apart should NOT trigger rapid burst (requires >= 3 in <= 120s)
        passed_tm = ("RULE-BULK-EXTRACT-01" not in out_tm.triggered_rules)
        findings.append({
            "test_case": "Sliding-Window Temporal Eviction (120s)",
            "category": "Temporal Behavior",
            "expected_behavior": "Access beyond 120s window avoids rapid burst trigger",
            "observed_behavior": f"Detected={out_tm.detected}, Rules={out_tm.triggered_rules}",
            "passed": passed_tm,
            "dimension": "Sliding Deque Eviction",
        })

        # 5. Automated Pagination Table Scraping
        page_events = [
            EventTelemetry(
                event_id=f"evt-pg-{p}",
                scenario_id="scen-test-pg",
                timestamp_epoch_ms=20000 + (p * 500),
                http_method="GET",
                url=f"/api/v1/transactions?accountId=acc_1&page={p}&size=50",
                normalized_route="/api/v1/transactions",
                status_code=200,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_att",
                sensitivity="CONFIDENTIAL",
                page_number=p,
                page_size=50,
                response_bytes=15000,
            )
            for p in range(1, 4)
        ]
        out_pg, _ = detector.evaluate_scenario("scen-test-pg", page_events)
        passed_pg = ("RULE-ADV-EXTRACT-01" in out_pg.triggered_rules)
        findings.append({
            "test_case": "Automated Pagination Table Scraping",
            "category": "API Behavior",
            "expected_behavior": "Rapid access across >= 3 distinct pages triggers RULE-ADV-EXTRACT-01",
            "observed_behavior": f"Detected={out_pg.detected}, Rules={out_pg.triggered_rules}",
            "passed": passed_pg,
            "dimension": "Pagination Harvesting",
        })

        # 6. Missing Resource Ownership Uncertainty
        unc_events = [
            EventTelemetry(
                event_id="evt-unc-1",
                scenario_id="scen-test-unc",
                timestamp_epoch_ms=30000,
                http_method="GET",
                url="/api/v1/customers/cust_999",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_999",
                auth_subject="usr_999",
                tenant_id="tenant_1",
                source_ip="10.0.0.1",
                customer_id="cust_999",
                resource_owner_id=None,  # Missing ownership!
                sensitivity="CONFIDENTIAL",
                response_bytes=300,
            )
        ]
        out_unc, _ = detector.evaluate_scenario("scen-test-unc", unc_events)
        passed_unc = out_unc.is_uncertain
        findings.append({
            "test_case": "Missing Resource Ownership Uncertainty",
            "category": "Uncertainty & Incomplete Evidence",
            "expected_behavior": "Missing customer ownership on customer route flagged as UNCERTAIN",
            "observed_behavior": f"is_uncertain={out_unc.is_uncertain}, explanation={out_unc.explanation}",
            "passed": passed_unc,
            "dimension": "Uncertainty Invariant",
        })

        # 7. Multi-Stage Kill-Chain Progression
        camp_events = [
            EventTelemetry(
                event_id="evt-cmp-1",
                scenario_id="scen-test-cmp",
                timestamp_epoch_ms=40000,
                http_method="GET",
                url="/actuator/env",
                normalized_route="/actuator/env",
                status_code=404,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id=None,
                sensitivity="UNKNOWN",
                response_bytes=90,
            ),
            EventTelemetry(
                event_id="evt-cmp-2",
                scenario_id="scen-test-cmp",
                timestamp_epoch_ms=45000,
                http_method="GET",
                url="/api/v1/accounts/acc_vic",
                normalized_route="/api/v1/accounts/{id}",
                status_code=403,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_vic",
                sensitivity="CONFIDENTIAL",
                response_bytes=130,
            ),
            EventTelemetry(
                event_id="evt-cmp-3",
                scenario_id="scen-test-cmp",
                timestamp_epoch_ms=50000,
                http_method="GET",
                url="/api/v1/customers/cust_vic_tgt",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id="usr_att",
                auth_subject="usr_att",
                tenant_id="tenant_1",
                source_ip="198.51.100.1",
                customer_id="cust_att",
                resource_owner_id="cust_vic_tgt",
                sensitivity="CONFIDENTIAL",
                response_bytes=600,
            ),
        ]
        out_cmp, _ = detector.evaluate_scenario("scen-test-cmp", camp_events)
        passed_cmp = (out_cmp.campaign_identified and "DATA_EXFILTRATION_CAMPAIGN" in out_cmp.triggered_rules)
        findings.append({
            "test_case": "Multi-Stage Kill-Chain Progression",
            "category": "Campaign Correlation",
            "expected_behavior": "Recon (404) + Probing (403) + Extraction (200) escalated to DATA_EXFILTRATION_CAMPAIGN",
            "observed_behavior": f"campaign_identified={out_cmp.campaign_identified}, Rules={out_cmp.triggered_rules}",
            "passed": passed_cmp,
            "dimension": "Multi-Stage Correlator",
        })

        return findings
