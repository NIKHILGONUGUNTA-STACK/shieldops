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

class RuleInj01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleInj01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        rule = new RuleInj01(stateStore, true, 1, 180);
    }

    @Test
    @DisplayName("Should trigger HIGH severity on SQL injection pattern in request path")
    void testSqlInjectionTrigger() {
        String attackerId = "cust-sqli-01";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/customers/1000' OR '1'='1", null, "NONE", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-INJ-01");
        assertThat(res.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(res.targetEntityValue()).isEqualTo(attackerId);

        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("HIGH");
        assertThat(evidence.confidenceScore()).isEqualTo(0.90);
    }

    @Test
    @DisplayName("Should trigger on UNION SELECT injection attack")
    void testUnionSelectInjectionTrigger() {
        String attackerId = "cust-sqli-02";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/accounts/1 UNION SELECT * FROM customers", null, "NONE", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence()).isPresent();
    }

    @Test
    @DisplayName("Should trigger on Path Traversal pattern")
    void testPathTraversalTrigger() {
        String attackerId = "cust-trav-01";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/customers/../../etc/passwd", null, "NONE", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence().get().triggerCondition()).contains("PATH_TRAVERSAL");
    }

    @Test
    @DisplayName("Should trigger on Command Injection pattern")
    void testCommandInjectionTrigger() {
        String attackerId = "cust-cmd-01";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/transfers/ref;cat /etc/shadow", null, "NONE", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence().get().triggerCondition()).contains("COMMAND_INJECTION");
    }

    @Test
    @DisplayName("Should trigger on Cross-Site Scripting (XSS) pattern")
    void testXssInjectionTrigger() {
        String attackerId = "cust-xss-01";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/customers/<script>alert(1)</script>", null, "NONE", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence().get().triggerCondition()).contains("CROSS_SITE_SCRIPTING");
    }

    @Test
    @DisplayName("Should trigger when flagged by TelemetryFilter INJECTION_INDICATOR")
    void testTelemetryAnomalyFlagTrigger() {
        String attackerId = "cust-flag-01";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/accounts", null, "INJECTION_INDICATOR", Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
    }

    @Test
    @DisplayName("Should escalate to CRITICAL severity when >= 3 injection attempts occur")
    void testCriticalEscalationOnRepeatedAttempts() {
        String attackerId = "cust-sqli-03";
        Instant now = Instant.now();

        RuleEvaluationResult lastRes = null;
        for (int i = 1; i <= 3; i++) {
            ApiEvent ev = createInjEvent(attackerId, "/api/v1/customers/1000' OR '1'='1--" + i, null, "NONE", now.minusSeconds(10 - i));
            lastRes = rule.evaluate(ev);
        }

        assertThat(lastRes).isNotNull();
        assertThat(lastRes.triggered()).isTrue();
        DetectionEvidence evidence = lastRes.evidence().get();
        assertThat(evidence.severity()).isEqualTo("CRITICAL");
        assertThat(evidence.confidenceScore()).isEqualTo(0.95);
    }

    @Test
    @DisplayName("Should not trigger on legitimate customer UUID path")
    void testLegitimateUuidDoesNotTrigger() {
        ApiEvent ev = createInjEvent("cust-1", "/api/v1/customers/10000000-0000-4000-8000-000000000001", null, "NONE", Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger on legitimate account number format")
    void testLegitimateAccountReferenceDoesNotTrigger() {
        ApiEvent ev = createInjEvent("cust-1", "/api/v1/accounts/ACCT-1001-SAVINGS", null, "NONE", Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger on benign financial phrase containing 'union'")
    void testBenignWordUnionDoesNotTrigger() {
        // e.g. path or description referencing Credit Union without SQL keywords
        ApiEvent ev = createInjEvent("cust-1", "/api/v1/transfers/credit-union-payment", null, "NONE", Instant.now());
        assertThat(rule.evaluate(ev).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should deduplicate repeated deliveries of the same event ID")
    void testEventDeduplication() {
        String attackerId = "cust-sqli-04";
        ApiEvent ev = createInjEvent(attackerId, "/api/v1/customers/1' OR '1'='1", null, "NONE", Instant.now());

        // First evaluation triggers (threshold 1)
        assertThat(rule.evaluate(ev).triggered()).isTrue();

        // Repeated delivery of same event does not increment count
        RuleEvaluationResult res = rule.evaluate(ev);
        assertThat(res.evidence().get().observedCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should return not triggered when rule is disabled")
    void testRuleDisabled() {
        RuleInj01 disabled = new RuleInj01(stateStore, false, 1, 180);
        ApiEvent ev = createInjEvent("cust-1", "/api/v1/customers/1' OR '1'='1", null, "NONE", Instant.now());
        assertThat(disabled.evaluate(ev).triggered()).isFalse();
    }

    private ApiEvent createInjEvent(String customerId, String path, String resourceId, String anomalyFlags, Instant timestamp) {
        boolean hasCustomer = customerId != null && !customerId.isBlank();
        return new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            "192.168.1.100",
            "GET",
            path,
            path,
            400,
            12,
            hasCustomer ? "sub-" + customerId : "anonymous",
            hasCustomer ? "ROLE_CUSTOMER" : "",
            customerId,
            "Mozilla/5.0",
            null,
            anomalyFlags,
            "CUSTOMER",
            resourceId,
            "INJECTION_INDICATOR".equals(anomalyFlags) ? "INJECTION_DETECTED" : null,
            50,
            0
        );
    }
}
