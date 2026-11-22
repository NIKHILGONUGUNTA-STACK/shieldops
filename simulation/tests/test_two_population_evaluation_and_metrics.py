"""Tests for Phase 7.3.6.1 Gate 2: Two-Population Evaluation Engine, Exact McNemar Testing, and Statistical Metrics.

Validates:
1. Reconciled full-population accounting (150 primary binary + 50 ambiguous/incomplete = 200 total).
2. Primary binary population confusion matrix isolation (TP, FP, TN, FN sum to 150).
3. Correct mathematical separation of True FPR = FP / (FP + TN) from FDR = FP / (TP + FP).
4. Secondary population explicit dispositions (50 samples = abstained + flagged + passed).
5. Exact two-sided McNemar test and non-parametric bootstrap confidence intervals.
6. Clean ablation protocol (NO_AUTH_OUTCOME removes signal without modifying telemetry status codes).
7. Dynamic executable robustness suite execution.
"""

import pytest
from simulation.evaluation.contextual_detector import AblationConfig, ContextualDetector
from simulation.evaluation.evaluation_engine import ResearchEvaluationEngine
from simulation.evaluation.isolated_detector import IsolatedRuleDetector
from simulation.evaluation.models import (
    ClassificationOutcome,
    DatasetManifest,
    EvaluationUnit,
    EventTelemetry,
    GroundTruthArtifact,
    GroundTruthCategory,
    ScenarioDefinition,
    ScenarioGroundTruth,
    UnitEvaluation,
)
from simulation.evaluation.statistical_metrics import (
    calculate_accuracy,
    calculate_f1,
    calculate_fdr,
    calculate_fnr,
    calculate_fpr,
    calculate_precision,
    calculate_recall,
    calculate_specificity,
    compile_metric_report,
    compile_population_accounting,
    compile_uncertainty_report,
    compute_bootstrap_ci,
    compute_paired_comparison,
    compute_wilson_score_interval,
    exact_mcnemar_test,
)


def _build_test_dataset():
    """Builds a deterministic in-memory dataset of 200 scenarios:

    - 80 Benign
    - 70 Malicious
    - 30 Ambiguous
    - 20 Incomplete
    """
    scenarios = []
    telemetry_map = {}

    # 1. 80 Benign scenarios (normal operations)
    # 70 completely clean, 10 have legitimate 403 role-denials (causes Isolated FP, but Contextual knows it's self-owned)
    for i in range(80):
        sc_id = f"test-benign-{i:03d}"
        scenarios.append(
            ScenarioGroundTruth(
                scenario_id=sc_id,
                scenario_family="NORMAL_TRAFFIC",
                scenario_name=f"Benign Traffic {i}",
                category=GroundTruthCategory.BENIGN,
                expected_detection=False,
                expected_campaign=False,
                expected_rules=[],
                seed=1000 + i,
                num_requests=3,
                num_identities=1,
                num_tenants=1,
                num_resources=1,
                duration_seconds=10.0,
                description="Normal benign traffic",
            )
        )
        has_role_denial = (i < 10)
        status_code = 403 if has_role_denial else 200
        url = f"/api/v1/customers/admin_settings" if has_role_denial else f"/api/v1/customers/cust_{i}"

        telemetry_map[sc_id] = [
            EventTelemetry(
                event_id=f"evt-b-{i}-1",
                scenario_id=sc_id,
                timestamp_epoch_ms=1000,
                http_method="GET",
                url=url,
                normalized_route="/api/v1/customers/{id}",
                status_code=status_code,
                user_id=f"usr_{i}",
                auth_subject=f"usr_{i}",
                tenant_id=f"tenant_{i}",
                source_ip="192.168.1.10",
                customer_id=f"cust_{i}",
                resource_owner_id=f"cust_{i}",  # Self-owned: no ownership mismatch!
                sensitivity="INTERNAL",
                response_bytes=250,
            )
        ]

    # 2. 70 Malicious scenarios (attacks)
    for i in range(70):
        sc_id = f"test-malicious-{i:03d}"
        scenarios.append(
            ScenarioGroundTruth(
                scenario_id=sc_id,
                scenario_family="BOLA_EXPLOITATION",
                scenario_name=f"BOLA Attack {i}",
                category=GroundTruthCategory.MALICIOUS,
                expected_detection=True,
                expected_campaign=False,
                expected_rules=["RULE_BOLA_CROSS_OWNER"],
                seed=2000 + i,
                num_requests=3,
                num_identities=1,
                num_tenants=1,
                num_resources=3,
                duration_seconds=15.0,
                description="BOLA IDOR cross-tenant access",
            )
        )
        # Multiple cross-owner requests triggering behavioral detection
        telemetry_map[sc_id] = [
            EventTelemetry(
                event_id=f"evt-m-{i}-{j}",
                scenario_id=sc_id,
                timestamp_epoch_ms=2000 + j * 5000,
                http_method="GET",
                url=f"/api/v1/customers/victim_{i}_{j}",
                normalized_route="/api/v1/customers/{id}",
                status_code=200,
                user_id=f"attacker_{i}",
                auth_subject=f"attacker_{i}",
                tenant_id=f"tenant_{i}",
                source_ip="10.0.0.99",
                customer_id=f"attacker_{i}",  # Attacker identity
                resource_owner_id=f"victim_{i}_{j}",  # Foreign victim cross-owner!
                sensitivity="CONFIDENTIAL",
                response_bytes=1200,
            )
            for j in range(4)
        ]

    # 3. 30 Ambiguous scenarios
    for i in range(30):
        sc_id = f"test-ambig-{i:03d}"
        scenarios.append(
            ScenarioGroundTruth(
                scenario_id=sc_id,
                scenario_family="SHARED_NAT_SPIKE",
                scenario_name=f"Ambiguous Traffic {i}",
                category=GroundTruthCategory.AMBIGUOUS,
                expected_detection=False,
                expected_campaign=False,
                expected_rules=[],
                seed=3000 + i,
                num_requests=5,
                num_identities=3,
                num_tenants=1,
                num_resources=2,
                duration_seconds=30.0,
                description="Ambiguous multi-user shared IP traffic",
            )
        )
        telemetry_map[sc_id] = [
            EventTelemetry(
                event_id=f"evt-a-{i}-1",
                scenario_id=sc_id,
                timestamp_epoch_ms=3000,
                http_method="GET",
                url=f"/api/v1/customers/cust_a_{i}",
                normalized_route="/api/v1/customers/{id}",
                status_code=403,
                user_id=f"usr_a_{i}",
                auth_subject=f"usr_a_{i}",
                tenant_id=f"tenant_{i}",
                source_ip="203.0.113.1",
                customer_id=f"cust_a_{i}",
                resource_owner_id=f"cust_a_{i}",
                sensitivity="INTERNAL",
                response_bytes=100,
            )
        ]

    # 4. 20 Incomplete scenarios
    for i in range(20):
        sc_id = f"test-incomp-{i:03d}"
        scenarios.append(
            ScenarioGroundTruth(
                scenario_id=sc_id,
                scenario_family="MISSING_TELEMETRY",
                scenario_name=f"Incomplete Traffic {i}",
                category=GroundTruthCategory.INCOMPLETE_EVIDENCE,
                expected_detection=False,
                expected_campaign=False,
                expected_rules=[],
                seed=4000 + i,
                num_requests=1,
                num_identities=0,
                num_tenants=0,
                num_resources=1,
                duration_seconds=1.0,
                description="Incomplete telemetry with missing identity and customer",
            )
        )
        telemetry_map[sc_id] = [
            EventTelemetry(
                event_id=f"evt-inc-{i}-1",
                scenario_id=sc_id,
                timestamp_epoch_ms=4000,
                http_method="GET",
                url="/api/v1/public/health",
                normalized_route="/api/v1/public/health",
                status_code=200,
                user_id=None,
                auth_subject=None,
                tenant_id=None,
                source_ip="192.168.1.1",
                customer_id=None,
                resource_owner_id=None,
                sensitivity="PUBLIC",
                response_bytes=50,
            )
        ]

    definitions = [
        ScenarioDefinition(
            scenario_id=s.scenario_id,
            seed=s.seed,
            num_requests=s.num_requests,
            num_identities=s.num_identities,
            num_tenants=s.num_tenants,
            num_resources=s.num_resources,
            duration_seconds=s.duration_seconds,
        )
        for s in scenarios
    ]

    manifest = DatasetManifest(
        dataset_id="DS-TEST-V1-1",
        version="1.1",
        created_at="2026-11-22T00:00:00Z",
        manifest_hash="test-manifest-hash",
        telemetry_hash="test-telemetry-hash",
        ground_truth_hash="test-gt-hash",
        scenario_definitions_hash="test-defs-hash",
        total_scenarios=200,
        benign_count=80,
        malicious_count=70,
        ambiguous_count=30,
        incomplete_count=20,
        scenarios=[],
        scenario_definitions=definitions,
    )

    ground_truth = GroundTruthArtifact(
        dataset_id="DS-TEST-V1-1",
        version="1.1",
        created_at="2026-11-22T00:00:00Z",
        ground_truth_hash="test-gt-hash",
        total_scenarios=200,
        population_distribution={"BENIGN": 80, "MALICIOUS": 70, "AMBIGUOUS": 30, "INCOMPLETE_EVIDENCE": 20},
        scenarios=scenarios,
    )

    return manifest, ground_truth, telemetry_map


class TestTwoPopulationEvaluationAndMetrics:
    """Test suite for Gate 2 two-population evaluation, statistical testing, and metrics."""

    def test_population_accounting_reconciliation(self):
        """Verifies that full population accounting reconciles 150 primary binary + 50 secondary = 200."""
        pop = compile_population_accounting(
            total_dataset_size=200,
            binary_count=150,
            benign_count=80,
            malicious_count=70,
            ambiguous_count=30,
            incomplete_count=20,
        )

        assert pop.total_dataset_size == 200
        assert pop.primary_binary_evaluated == 150
        assert pop.binary_benign_count == 80
        assert pop.binary_malicious_count == 70
        assert pop.ambiguous_evaluated == 30
        assert pop.incomplete_evaluated == 20
        assert pop.binary_coverage_ratio == 0.75
        assert pop.accounting_reconciled is True

    def test_primary_binary_population_confusion_matrix_isolation(self):
        """Verifies that the primary binary evaluation evaluates strictly 150 scenarios (TP+FP+TN+FN=150)."""
        manifest, ground_truth, telemetry = _build_test_dataset()
        engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=ground_truth)
        result = engine.run_full_evaluation()

        iso_cm = result.isolated_scenario_metrics.confusion_matrix
        ctx_cm = result.contextual_scenario_metrics.confusion_matrix

        # Total primary binary samples must strictly equal 150
        assert iso_cm.true_positives + iso_cm.false_positives + iso_cm.true_negatives + iso_cm.false_negatives == 150
        assert ctx_cm.true_positives + ctx_cm.false_positives + ctx_cm.true_negatives + ctx_cm.false_negatives == 150

        # Benign (80) and Malicious (70) sums
        assert iso_cm.true_positives + iso_cm.false_negatives == 70
        assert iso_cm.false_positives + iso_cm.true_negatives == 80
        assert ctx_cm.true_positives + ctx_cm.false_negatives == 70
        assert ctx_cm.false_positives + ctx_cm.true_negatives == 80

    def test_fpr_vs_fdr_mathematical_distinction(self):
        """Verifies correct mathematical calculation separating True FPR (FP / (FP+TN)) from FDR (FP / (TP+FP))."""
        evals = [
            UnitEvaluation(
                unit=EvaluationUnit.SCENARIO_LEVEL,
                unit_id=f"tp-{i}",
                ground_truth_category=GroundTruthCategory.MALICIOUS,
                expected_detection=True,
                actual_detection=True,
                is_uncertain=False,
                classification=ClassificationOutcome.TP,
                triggered_rules=[],
                campaign_identified=False,
                explanation="",
            )
            for i in range(30)
        ] + [
            UnitEvaluation(
                unit=EvaluationUnit.SCENARIO_LEVEL,
                unit_id=f"fp-{i}",
                ground_truth_category=GroundTruthCategory.BENIGN,
                expected_detection=False,
                actual_detection=True,
                is_uncertain=False,
                classification=ClassificationOutcome.FP,
                triggered_rules=[],
                campaign_identified=False,
                explanation="",
            )
            for i in range(10)
        ] + [
            UnitEvaluation(
                unit=EvaluationUnit.SCENARIO_LEVEL,
                unit_id=f"tn-{i}",
                ground_truth_category=GroundTruthCategory.BENIGN,
                expected_detection=False,
                actual_detection=False,
                is_uncertain=False,
                classification=ClassificationOutcome.TN,
                triggered_rules=[],
                campaign_identified=False,
                explanation="",
            )
            for i in range(70)
        ] + [
            UnitEvaluation(
                unit=EvaluationUnit.SCENARIO_LEVEL,
                unit_id=f"fn-{i}",
                ground_truth_category=GroundTruthCategory.MALICIOUS,
                expected_detection=True,
                actual_detection=False,
                is_uncertain=False,
                classification=ClassificationOutcome.FN,
                triggered_rules=[],
                campaign_identified=False,
                explanation="",
            )
            for i in range(40)
        ]

        fpr = calculate_fpr(evals)
        fdr = calculate_fdr(evals)
        precision = calculate_precision(evals)
        recall = calculate_recall(evals)

        # FPR = FP / (FP + TN) = 10 / (10 + 70) = 10 / 80 = 0.125
        assert round(fpr, 4) == 0.1250

        # FDR = FP / (TP + FP) = 10 / (30 + 10) = 10 / 40 = 0.250
        assert round(fdr, 4) == 0.2500

        # Precision = 1 - FDR = 30 / 40 = 0.750
        assert round(precision, 4) == 0.7500
        assert round(fdr + precision, 4) == 1.0000

        # Recall = TP / (TP + FN) = 30 / 70 = 0.4286
        assert round(recall, 4) == 0.4286

        # In compile_metric_report, both are recorded independently
        report = compile_metric_report(evals)
        assert report.false_positive_rate == 0.1250
        assert report.false_discovery_rate == 0.2500
        assert report.false_positive_rate != report.false_discovery_rate

    def test_secondary_uncertainty_population_dispositions(self):
        """Verifies that the secondary population (50 samples) evaluates explicit dispositions."""
        evals = [
            UnitEvaluation(
                unit=EvaluationUnit.UNCERTAINTY_HANDLING,
                unit_id=f"unc-{i}",
                ground_truth_category=GroundTruthCategory.AMBIGUOUS if i < 30 else GroundTruthCategory.INCOMPLETE_EVIDENCE,
                expected_detection=False,
                actual_detection=False,
                is_uncertain=True,
                classification=ClassificationOutcome.UNCERTAIN_CORRECT,
                triggered_rules=[],
                campaign_identified=False,
                explanation="Safe abstention",
            )
            for i in range(28)
        ] + [
            UnitEvaluation(
                unit=EvaluationUnit.UNCERTAINTY_HANDLING,
                unit_id=f"over-{i}",
                ground_truth_category=GroundTruthCategory.AMBIGUOUS if i < 6 else GroundTruthCategory.INCOMPLETE_EVIDENCE,
                expected_detection=False,
                actual_detection=True,
                is_uncertain=False,
                classification=ClassificationOutcome.FP,
                triggered_rules=[],
                campaign_identified=False,
                explanation="Over-escalated",
            )
            for i in range(11)
        ] + [
            UnitEvaluation(
                unit=EvaluationUnit.UNCERTAINTY_HANDLING,
                unit_id=f"under-{i}",
                ground_truth_category=GroundTruthCategory.AMBIGUOUS if i < 6 else GroundTruthCategory.INCOMPLETE_EVIDENCE,
                expected_detection=False,
                actual_detection=False,
                is_uncertain=False,
                classification=ClassificationOutcome.UNCERTAIN_INCORRECT,
                triggered_rules=[],
                campaign_identified=False,
                explanation="Under-investigated",
            )
            for i in range(11)
        ]

        report = compile_uncertainty_report(evals, total_ambiguous=30, total_incomplete=20)

        assert report.total_samples == 50
        assert report.abstained_uncertain == 28
        assert report.flagged_malicious == 11
        assert report.passed_benign == 11
        assert report.abstained_uncertain + report.flagged_malicious + report.passed_benign == 50
        assert report.abstention_rate == 0.56
        assert report.over_escalation_rate == 0.22
        assert report.under_investigation_rate == 0.22
        assert report.ci_abstention is not None
        assert report.ci_abstention.lower <= report.ci_abstention.point_estimate <= report.ci_abstention.upper

    def test_exact_mcnemar_test_binomial_computation(self):
        """Verifies exact two-sided McNemar test against known mathematical probabilities."""
        def _make_evals(b: int, c: int, a: int = 50, d: int = 0):
            # Creates paired evaluations resulting in contingency table:
            # a: both correct
            # b: iso correct, ctx incorrect
            # c: iso incorrect, ctx correct
            # d: both incorrect
            iso_list, ctx_list = [], []
            uid = 0

            # Both correct (a)
            for _ in range(a):
                uid += 1
                iso_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=True, is_uncertain=False, classification=ClassificationOutcome.TP, triggered_rules=[], campaign_identified=False, explanation=""))
                ctx_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=True, is_uncertain=False, classification=ClassificationOutcome.TP, triggered_rules=[], campaign_identified=False, explanation=""))

            # Iso correct, Ctx incorrect (b)
            for _ in range(b):
                uid += 1
                iso_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=True, is_uncertain=False, classification=ClassificationOutcome.TP, triggered_rules=[], campaign_identified=False, explanation=""))
                ctx_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=False, is_uncertain=False, classification=ClassificationOutcome.FN, triggered_rules=[], campaign_identified=False, explanation=""))

            # Iso incorrect, Ctx correct (c)
            for _ in range(c):
                uid += 1
                iso_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=False, is_uncertain=False, classification=ClassificationOutcome.FN, triggered_rules=[], campaign_identified=False, explanation=""))
                ctx_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=True, is_uncertain=False, classification=ClassificationOutcome.TP, triggered_rules=[], campaign_identified=False, explanation=""))

            # Both incorrect (d)
            for _ in range(d):
                uid += 1
                iso_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=False, is_uncertain=False, classification=ClassificationOutcome.FN, triggered_rules=[], campaign_identified=False, explanation=""))
                ctx_list.append(UnitEvaluation(unit=EvaluationUnit.SCENARIO_LEVEL, unit_id=f"u-{uid}", ground_truth_category=GroundTruthCategory.MALICIOUS, expected_detection=True, actual_detection=False, is_uncertain=False, classification=ClassificationOutcome.FN, triggered_rules=[], campaign_identified=False, explanation=""))

            return iso_list, ctx_list

        # Case 1: b=0, c=10 (highly discordant)
        # 2-sided exact p-value = 2 * (0.5)^10 = 2 / 1024 = 0.001953125
        iso1, ctx1 = _make_evals(b=0, c=10)
        _, b1, c1, _, p1, _, is_sig1 = exact_mcnemar_test(iso1, ctx1)
        assert b1 == 0 and c1 == 10
        assert round(p1, 6) == 0.001953
        assert is_sig1 is True

        # Case 2: b=5, c=5 (perfectly symmetric)
        iso2, ctx2 = _make_evals(b=5, c=5)
        _, b2, c2, _, p2, _, is_sig2 = exact_mcnemar_test(iso2, ctx2)
        assert b2 == 5 and c2 == 5
        assert p2 == 1.0
        assert is_sig2 is False

        # Case 3: b=0, c=0 (no discordant pairs)
        iso3, ctx3 = _make_evals(b=0, c=0)
        _, b3, c3, _, p3, _, is_sig3 = exact_mcnemar_test(iso3, ctx3)
        assert b3 == 0 and c3 == 0
        assert p3 == 1.0

        # Case 4: b=0, c=50 (Aegis vs Isolated on real dataset)
        iso4, ctx4 = _make_evals(b=0, c=50)
        _, b4, c4, _, p4, _, is_sig4 = exact_mcnemar_test(iso4, ctx4)
        assert b4 == 0 and c4 == 50
        assert p4 < 1e-12
        assert is_sig4 is True

    def test_paired_bootstrap_comparison(self):
        """Verifies paired scenario-level bootstrap produces non-zero valid confidence intervals."""
        manifest, ground_truth, telemetry = _build_test_dataset()
        engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=ground_truth)
        result = engine.run_full_evaluation()

        comp = result.paired_scenario_comparison
        assert comp.sample_size == 150
        assert comp.both_correct_a + comp.isolated_correct_contextual_incorrect_b + comp.isolated_incorrect_contextual_correct_c + comp.both_incorrect_d == 150
        assert comp.discordant_pairs_total == comp.isolated_correct_contextual_incorrect_b + comp.isolated_incorrect_contextual_correct_c

        # Delta metrics
        assert comp.delta_f1 > 0.0
        assert comp.ci_delta_f1 is not None
        assert comp.ci_delta_f1.lower <= comp.delta_f1 <= comp.ci_delta_f1.upper

        assert comp.delta_fpr <= 0.0
        assert comp.ci_delta_fpr is not None
        assert comp.ci_delta_fpr.lower <= comp.delta_fpr <= comp.ci_delta_fpr.upper

    def test_ablation_no_auth_outcome_does_not_mutate_status_code(self):
        """Verifies that NO_AUTH_OUTCOME ablation leaves HTTP status codes and telemetry events intact."""
        events = [
            EventTelemetry(
                event_id="evt-probe-1",
                scenario_id="scen-test",
                timestamp_epoch_ms=1000,
                http_method="GET",
                url="/api/v1/customers/cust_victim",
                normalized_route="/api/v1/customers/{id}",
                status_code=403,  # Blocked probe
                user_id="usr_attacker",
                auth_subject="usr_attacker",
                tenant_id="tenant_1",
                source_ip="192.168.1.50",
                customer_id="cust_victim",
                resource_owner_id="cust_victim",
                sensitivity="CONFIDENTIAL",
                response_bytes=100,
            )
        ]

        # Evaluate with baseline detector
        baseline_detector = ContextualDetector()
        _, base_outs = baseline_detector.evaluate_scenario("scen-test", events)

        # Raw event status code must remain 403
        assert events[0].status_code == 403

        # Evaluate with NO_AUTH_OUTCOME ablation
        ablation_detector = ContextualDetector(ablation=AblationConfig(disable_auth_outcome=True))
        _, abl_outs = ablation_detector.evaluate_scenario("scen-test", events)

        # Raw event status code must STILL remain 403 (unmutated!)
        assert events[0].status_code == 403
        assert len(abl_outs) == 1

    def test_dynamic_robustness_execution(self):
        """Verifies that dynamic robustness suite executes and validates edge-case dimensions."""
        manifest, ground_truth, telemetry = _build_test_dataset()
        engine = ResearchEvaluationEngine(manifest, telemetry, ground_truth=ground_truth)
        result = engine.run_full_evaluation()

        assert len(result.robustness_results) >= 7
        for finding in result.robustness_results:
            assert "test_case" in finding
            assert "category" in finding
            assert "passed" in finding
            assert finding["passed"] is True, f"Failed robustness case: {finding['test_case']}"
