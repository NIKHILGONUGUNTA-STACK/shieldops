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

class RuleRate01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleRate01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        rule = new RuleRate01(stateStore, true, 20, 60);
    }

    @Test
    @DisplayName("Should trigger MEDIUM incident when requests reach threshold in window")
    void testThresholdTrigger() {
        String customerId = "cust-rate-01";
        Instant now = Instant.now();

        RuleEvaluationResult res = null;
        for (int i = 1; i <= 20; i++) {
            ApiEvent ev = createRateEvent(customerId, "192.168.1.1", now.minusSeconds(25 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-RATE-01");
        assertThat(res.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(res.targetEntityValue()).isEqualTo(customerId);

        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("MEDIUM");
        assertThat(evidence.confidenceScore()).isEqualTo(0.80);
        assertThat(evidence.observedCount()).isEqualTo(20);
    }

    @Test
    @DisplayName("Should escalate to HIGH severity on extreme request burst (>= 40)")
    void testExtremeBurstEscalation() {
        String customerId = "cust-rate-02";
        Instant now = Instant.now();

        RuleEvaluationResult res = null;
        for (int i = 1; i <= 40; i++) {
            ApiEvent ev = createRateEvent(customerId, "192.168.1.2", now.minusSeconds(45 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("HIGH");
        assertThat(evidence.confidenceScore()).isEqualTo(0.90);
        assertThat(evidence.observedCount()).isEqualTo(40);
    }

    @Test
    @DisplayName("Should track by IP when caller is unauthenticated")
    void testUnauthenticatedTargetEntityIp() {
        String ip = "203.0.113.5";
        Instant now = Instant.now();

        RuleEvaluationResult res = null;
        for (int i = 1; i <= 20; i++) {
            ApiEvent ev = createRateEvent("", ip, now.minusSeconds(25 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        assertThat(res.targetEntityType()).isEqualTo("IP");
        assertThat(res.targetEntityValue()).isEqualTo(ip);
    }

    @Test
    @DisplayName("Should not trigger on normal interactive browsing (3-5 requests in window)")
    void testNormalTrafficDoesNotTrigger() {
        String customerId = "cust-rate-03";
        Instant now = Instant.now();

        for (int i = 1; i <= 5; i++) {
            ApiEvent ev = createRateEvent(customerId, "192.168.1.3", now.minusSeconds(10 - i));
            assertThat(rule.evaluate(ev).triggered()).isFalse();
        }
    }

    @Test
    @DisplayName("Should tolerate benign retries (2-3 retries on network blip)")
    void testBenignRetriesDoNotTrigger() {
        String customerId = "cust-rate-04";
        Instant now = Instant.now();

        for (int i = 1; i <= 3; i++) {
            ApiEvent ev = createRateEvent(customerId, "192.168.1.4", now.minusSeconds(5 - i));
            assertThat(rule.evaluate(ev).triggered()).isFalse();
        }
    }

    @Test
    @DisplayName("Should ignore actuator endpoints")
    void testActuatorEndpointsIgnored() {
        ApiEvent evActuator = new ApiEvent(
            UUID.randomUUID(), "cid-act", Instant.now(), "127.0.0.1", "GET",
            "/actuator/prometheus", "/actuator/prometheus", 200, 5,
            "anonymous", "", "", "Prometheus/2.54", null, "NONE", null, null, null, 5000, 0
        );

        RuleEvaluationResult res = rule.evaluate(evActuator);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should deduplicate repeated deliveries of the same event ID")
    void testEventDeduplication() {
        String customerId = "cust-rate-05";
        ApiEvent ev = createRateEvent(customerId, "192.168.1.5", Instant.now());

        // Evaluate same event 20 times
        for (int i = 0; i < 19; i++) {
            rule.evaluate(ev);
        }
        RuleEvaluationResult res = rule.evaluate(ev);

        // Distinct event count is only 1, so should not trigger
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should return not triggered when rule is disabled")
    void testRuleDisabled() {
        RuleRate01 disabled = new RuleRate01(stateStore, false, 20, 60);
        ApiEvent ev = createRateEvent("cust-1", "127.0.0.1", Instant.now());
        assertThat(disabled.evaluate(ev).triggered()).isFalse();
    }

    private ApiEvent createRateEvent(String customerId, String sourceIp, Instant timestamp) {
        boolean hasCustomer = customerId != null && !customerId.isBlank();
        return new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            sourceIp,
            "GET",
            "/api/v1/customers/profile",
            "/customers/profile",
            200,
            10,
            hasCustomer ? "sub-" + customerId : "anonymous",
            hasCustomer ? "ROLE_CUSTOMER" : "",
            customerId,
            "curl/8.0",
            null,
            "NONE",
            "CUSTOMER",
            null,
            null,
            250,
            1
        );
    }
}
