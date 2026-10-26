package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.state.InMemoryDetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RuleProbe01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleProbe01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        rule = new RuleProbe01(stateStore, true, 4, 180);
    }

    @Test
    @DisplayName("Should trigger when 4 probing failures occur across distinct paths")
    void testDistinctPathProbingTrigger() {
        String attackerId = "cust-probe-01";
        Instant now = Instant.now();

        String[] probePaths = {
            "/api/v1/admin/debug",
            "/api/v1/system/status",
            "/api/v1/customers/unknown-id",
            "/api/v1/internal/config"
        };

        RuleEvaluationResult res = null;
        for (int i = 0; i < probePaths.length; i++) {
            ApiEvent ev = createProbeEvent(attackerId, probePaths[i], "hash-" + i, 404, now.minusSeconds(10 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-PROBE-01");
        assertThat(res.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(res.targetEntityValue()).isEqualTo(attackerId);

        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("HIGH"); // >= 3 distinct paths
        assertThat(evidence.confidenceScore()).isEqualTo(0.90);
        assertThat(evidence.observedCount()).isEqualTo(4);
    }

    @Test
    @DisplayName("Should trigger on active parameter fuzzing with varying payload hashes")
    void testParameterFuzzingTrigger() {
        String attackerId = "cust-probe-02";
        Instant now = Instant.now();

        RuleEvaluationResult res = null;
        for (int i = 1; i <= 4; i++) {
            // Same path, but different payload hashes (fuzzing distinct inputs)
            ApiEvent ev = createProbeEvent(attackerId, "/api/v1/transfers", "fuzz-hash-" + i, 400, now.minusSeconds(10 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.observedCount()).isEqualTo(4);
    }

    @Test
    @DisplayName("Should mitigate benign client retry loop with identical payload hash and path")
    void testBenignIdenticalRetryLoopMitigation() {
        String customerId = "cust-retry-01";
        Instant now = Instant.now();

        // 4 repeated identical failures with exact same path and exact same payload hash (buggy client retry)
        for (int i = 1; i <= 4; i++) {
            ApiEvent ev = createProbeEvent(customerId, "/api/v1/transfers", "same-broken-payload-hash", 400, now.minusSeconds(10 - i));
            RuleEvaluationResult res = rule.evaluate(ev);
            // Should be suppressed due to benign identical retry loop mitigation (needs threshold + 3 = 7)
            assertThat(res.triggered()).isFalse();
        }
    }

    @Test
    @DisplayName("Should not trigger on single 404 (mistyped URL)")
    void testSingle404DoesNotTrigger() {
        ApiEvent ev = createProbeEvent("cust-1", "/api/v1/custmers", "none", 404, Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger on single 400 (validation failure)")
    void testSingle400DoesNotTrigger() {
        ApiEvent ev = createProbeEvent("cust-1", "/api/v1/transfers", "hash-err", 400, Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should deduplicate repeated deliveries of the same event ID")
    void testEventDeduplication() {
        String attackerId = "cust-probe-03";
        ApiEvent ev = createProbeEvent(attackerId, "/api/v1/unknown", "hash-1", 404, Instant.now());

        // Evaluate same event 5 times
        for (int i = 0; i < 4; i++) {
            rule.evaluate(ev);
        }
        RuleEvaluationResult res = rule.evaluate(ev);

        // Distinct count is only 1, so should not trigger
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore actuator endpoints")
    void testActuatorIgnored() {
        ApiEvent ev = createProbeEvent("cust-1", "/actuator/unknown-metric", "none", 404, Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should return not triggered when rule is disabled")
    void testRuleDisabled() {
        RuleProbe01 disabled = new RuleProbe01(stateStore, false, 4, 180);
        ApiEvent ev = createProbeEvent("cust-1", "/api/v1/unknown", "none", 404, Instant.now());
        assertThat(disabled.evaluate(ev).triggered()).isFalse();
    }

    private ApiEvent createProbeEvent(String customerId, String path, String payloadHash, int statusCode, Instant timestamp) {
        boolean hasCustomer = customerId != null && !customerId.isBlank();
        return new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            "192.168.1.100",
            "POST",
            path,
            path,
            statusCode,
            15,
            hasCustomer ? "sub-" + customerId : "anonymous",
            hasCustomer ? "ROLE_CUSTOMER" : "",
            customerId,
            "Mozilla/5.0",
            payloadHash,
            statusCode == 400 ? "VALIDATION_ERROR" : "NONE",
            "API_ROUTE",
            null,
            statusCode == 400 ? "VALIDATION_ERROR" : "NOT_FOUND",
            50,
            0
        );
    }
}
