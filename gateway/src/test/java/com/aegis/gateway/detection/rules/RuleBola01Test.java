package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

class RuleBola01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleBola01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        rule = new RuleBola01(stateStore, true, 3, 300, 2);
    }

    @Test
    @DisplayName("Should trigger HIGH severity when threshold and min distinct resources are reached")
    void testThresholdTriggerWithDistinctResources() {
        String attackerId = "cust-attacker-01";
        Instant now = Instant.now();

        // Attempt 1: cust-victim-A
        ApiEvent event1 = createBolaEvent(attackerId, "cust-victim-A", now.minusSeconds(10));
        RuleEvaluationResult res1 = rule.evaluate(event1);
        assertThat(res1.triggered()).isFalse();

        // Attempt 2: cust-victim-B
        ApiEvent event2 = createBolaEvent(attackerId, "cust-victim-B", now.minusSeconds(5));
        RuleEvaluationResult res2 = rule.evaluate(event2);
        assertThat(res2.triggered()).isFalse();

        // Attempt 3: cust-victim-C (Threshold 3 reached, 3 distinct resources)
        ApiEvent event3 = createBolaEvent(attackerId, "cust-victim-C", now);
        RuleEvaluationResult res3 = rule.evaluate(event3);

        assertThat(res3.triggered()).isTrue();
        assertThat(res3.ruleId()).isEqualTo("RULE-BOLA-01");
        assertThat(res3.ruleVersion()).isEqualTo("1.0.0");
        assertThat(res3.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(res3.targetEntityValue()).isEqualTo(attackerId);

        assertThat(res3.evidence()).isPresent();
        DetectionEvidence ev = res3.evidence().get();
        assertThat(ev.severity()).isEqualTo("HIGH");
        assertThat(ev.confidenceScore()).isEqualTo(0.95);
        assertThat(ev.observedCount()).isEqualTo(3);
        assertThat(ev.distinctResources()).isEqualTo(3);
        assertThat(ev.windowSeconds()).isEqualTo(300);
        assertThat(ev.contributingEventIds())
            .containsExactlyInAnyOrder(event1.id(), event2.id(), event3.id());
    }

    @Test
    @DisplayName("Should not trigger when attempts are below threshold")
    void testBelowThresholdDoesNotTrigger() {
        String attackerId = "cust-attacker-02";
        Instant now = Instant.now();

        ApiEvent event1 = createBolaEvent(attackerId, "cust-victim-A", now.minusSeconds(10));
        ApiEvent event2 = createBolaEvent(attackerId, "cust-victim-B", now);

        assertThat(rule.evaluate(event1).triggered()).isFalse();
        assertThat(rule.evaluate(event2).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger high-severity BOLA if attempts target only a single resource repeatedly below secondary threshold")
    void testSameResourceRepeatedDoesNotTriggerHighConfidence() {
        String attackerId = "cust-attacker-03";
        String sameVictim = "cust-victim-single";
        Instant now = Instant.now();

        // 3 attempts against the SAME resource (distinct resources = 1 < minDistinctResources 2)
        ApiEvent e1 = createBolaEvent(attackerId, sameVictim, now.minusSeconds(20));
        ApiEvent e2 = createBolaEvent(attackerId, sameVictim, now.minusSeconds(10));
        ApiEvent e3 = createBolaEvent(attackerId, sameVictim, now);

        assertThat(rule.evaluate(e1).triggered()).isFalse();
        assertThat(rule.evaluate(e2).triggered()).isFalse();
        RuleEvaluationResult res3 = rule.evaluate(e3);
        assertThat(res3.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should trigger secondary MEDIUM severity when single resource is targeted excessively (>= threshold + 2)")
    void testExcessiveSingleResourceTriggersMediumSeverity() {
        String attackerId = "cust-attacker-04";
        String sameVictim = "cust-victim-single";
        Instant now = Instant.now();

        for (int i = 0; i < 4; i++) {
            ApiEvent e = createBolaEvent(attackerId, sameVictim, now.minusSeconds(50 - (i * 10)));
            assertThat(rule.evaluate(e).triggered()).isFalse();
        }

        // 5th attempt (threshold + 2 = 5)
        ApiEvent e5 = createBolaEvent(attackerId, sameVictim, now);
        RuleEvaluationResult res5 = rule.evaluate(e5);

        assertThat(res5.triggered()).isTrue();
        assertThat(res5.evidence()).isPresent();
        DetectionEvidence ev5 = res5.evidence().get();
        assertThat(ev5.severity()).isEqualTo("MEDIUM");
        assertThat(ev5.confidenceScore()).isEqualTo(0.80);
        assertThat(ev5.observedCount()).isEqualTo(5);
        assertThat(ev5.distinctResources()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should ignore unauthenticated or anonymous attempts")
    void testMissingCustomerContextIgnored() {
        ApiEvent anonymousEvent = new ApiEvent(
            UUID.randomUUID(), "req-anon", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/cust-victim-A", "route-customer", 403, 12,
            "", "", "", "curl", null, "NONE", "CUSTOMER", "cust-victim-A", "BOLA_VIOLATION", 0, 0
        );

        RuleEvaluationResult res = rule.evaluate(anonymousEvent);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore 403 when customer accesses their own resource (non-cross-customer)")
    void testAccessingOwnResourceIgnored() {
        String customerId = "cust-legit-01";
        ApiEvent ownResourceEvent = new ApiEvent(
            UUID.randomUUID(), "req-own", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/" + customerId, "route-customer", 403, 12,
            "sub-legit", "ROLE_CUSTOMER", customerId, "curl", null, "NONE",
            "CUSTOMER", customerId, null, 0, 0
        );

        RuleEvaluationResult res = rule.evaluate(ownResourceEvent);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore generic 403 on non-tenant routes such as security admin endpoints")
    void testGeneric403SecurityEndpointIgnored() {
        String customerId = "cust-user-01";
        ApiEvent securityEndpoint403 = new ApiEvent(
            UUID.randomUUID(), "req-sec", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/security/events", "route-security", 403, 8,
            "sub-user", "ROLE_CUSTOMER", customerId, "curl", null, "NONE",
            null, null, "INSUFFICIENT_ROLE", 0, 0
        );

        RuleEvaluationResult res = rule.evaluate(securityEndpoint403);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore successful (200) and server error (500) requests")
    void testNon403Ignored() {
        String customerId = "cust-user-02";
        ApiEvent successEvent = new ApiEvent(
            UUID.randomUUID(), "req-ok", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/cust-victim-A", "route-customer", 200, 15,
            "sub-user", "ROLE_CUSTOMER", customerId, "curl", null, "NONE",
            "CUSTOMER", "cust-victim-A", null, 256, 1
        );

        ApiEvent serverErrorEvent = new ApiEvent(
            UUID.randomUUID(), "req-err", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/cust-victim-A", "route-customer", 500, 45,
            "sub-user", "ROLE_CUSTOMER", customerId, "curl", null, "NONE",
            "CUSTOMER", "cust-victim-A", null, 0, 0
        );

        assertThat(rule.evaluate(successEvent).triggered()).isFalse();
        assertThat(rule.evaluate(serverErrorEvent).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should prune events outside the sliding window")
    void testWindowExpiration() {
        String attackerId = "cust-attacker-05";
        Instant now = Instant.now();

        // 2 attempts outside the 300s window (400s and 350s ago)
        ApiEvent old1 = createBolaEvent(attackerId, "cust-victim-A", now.minusSeconds(400));
        ApiEvent old2 = createBolaEvent(attackerId, "cust-victim-B", now.minusSeconds(350));
        rule.evaluate(old1);
        rule.evaluate(old2);

        // 1 attempt now (within window) -> window count is only 1!
        ApiEvent recent = createBolaEvent(attackerId, "cust-victim-C", now);
        RuleEvaluationResult res = rule.evaluate(recent);

        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should isolate state between different customers")
    void testCustomerPartitioning() {
        Instant now = Instant.now();

        ApiEvent a1 = createBolaEvent("cust-A", "cust-victim-1", now.minusSeconds(10));
        ApiEvent a2 = createBolaEvent("cust-A", "cust-victim-2", now);

        ApiEvent b1 = createBolaEvent("cust-B", "cust-victim-3", now.minusSeconds(10));
        ApiEvent b2 = createBolaEvent("cust-B", "cust-victim-4", now);

        assertThat(rule.evaluate(a1).triggered()).isFalse();
        assertThat(rule.evaluate(a2).triggered()).isFalse();
        assertThat(rule.evaluate(b1).triggered()).isFalse();
        assertThat(rule.evaluate(b2).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger when rule is disabled")
    void testRuleDisabled() {
        RuleBola01 disabledRule = new RuleBola01(stateStore, false, 3, 300, 2);
        String attackerId = "cust-attacker-06";
        Instant now = Instant.now();

        for (int i = 0; i < 5; i++) {
            ApiEvent e = createBolaEvent(attackerId, "cust-victim-" + i, now.minusSeconds(10 - i));
            RuleEvaluationResult res = disabledRule.evaluate(e);
            assertThat(res.triggered()).isFalse();
        }
    }

    private ApiEvent createBolaEvent(String customerId, String victimResourceId, Instant timestamp) {
        return new ApiEvent(
            UUID.randomUUID(),
            "req-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            "192.168.1.100",
            "GET",
            "/api/v1/customers/" + victimResourceId,
            "customer-service-route",
            403,
            15,
            "sub-" + customerId,
            "ROLE_CUSTOMER",
            customerId,
            "Mozilla/5.0",
            null,
            "NONE",
            "CUSTOMER",
            victimResourceId,
            "BOLA_VIOLATION",
            0,
            0
        );
    }

    static class InMemoryDetectionStateStore implements DetectionStateStore {
        private final Map<String, List<BolaAttemptRecord>> store = new ConcurrentHashMap<>();

        @Override
        public void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp) {
            store.computeIfAbsent(customerId, k -> new CopyOnWriteArrayList<>())
                .add(new BolaAttemptRecord(eventId, resourceId, timestamp));
        }

        @Override
        public List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since) {
            List<BolaAttemptRecord> records = store.getOrDefault(customerId, Collections.emptyList());
            return records.stream()
                .filter(r -> !r.timestamp().isBefore(since))
                .toList();
        }

        @Override
        public void clear(String customerId) {
            store.remove(customerId);
        }
    }
}
