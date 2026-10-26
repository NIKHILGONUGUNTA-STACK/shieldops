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

class RuleAuth01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleAuth01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        rule = new RuleAuth01(stateStore, true, 5, 120);
    }

    @Test
    @DisplayName("Should trigger MEDIUM incident when 5 authentication failures occur within window")
    void testThresholdTrigger() {
        String attackerIp = "192.168.1.50";
        Instant now = Instant.now();

        for (int i = 1; i <= 4; i++) {
            ApiEvent ev = createAuthEvent(attackerIp, "anonymous", 401, now.minusSeconds(20 - i));
            RuleEvaluationResult res = rule.evaluate(ev);
            assertThat(res.triggered()).isFalse();
        }

        // 5th failure reaches threshold
        ApiEvent triggerEv = createAuthEvent(attackerIp, "anonymous", 401, now);
        RuleEvaluationResult res = rule.evaluate(triggerEv);

        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-AUTH-01");
        assertThat(res.targetEntityType()).isEqualTo("IP");
        assertThat(res.targetEntityValue()).isEqualTo(attackerIp);

        assertThat(res.evidence()).isPresent();
        DetectionEvidence ev = res.evidence().get();
        assertThat(ev.severity()).isEqualTo("MEDIUM");
        assertThat(ev.confidenceScore()).isEqualTo(0.85);
        assertThat(ev.observedCount()).isEqualTo(5);
        assertThat(ev.windowSeconds()).isEqualTo(120);
    }

    @Test
    @DisplayName("Should escalate to HIGH severity when >= 10 authentication failures occur")
    void testHighBurstEscalation() {
        String attackerIp = "192.168.1.51";
        Instant now = Instant.now();

        RuleEvaluationResult lastRes = null;
        for (int i = 1; i <= 10; i++) {
            ApiEvent ev = createAuthEvent(attackerIp, "anonymous", 401, now.minusSeconds(15 - i));
            lastRes = rule.evaluate(ev);
        }

        assertThat(lastRes).isNotNull();
        assertThat(lastRes.triggered()).isTrue();
        DetectionEvidence ev = lastRes.evidence().get();
        assertThat(ev.severity()).isEqualTo("HIGH");
        assertThat(ev.confidenceScore()).isEqualTo(0.95);
        assertThat(ev.observedCount()).isEqualTo(10);
    }

    @Test
    @DisplayName("Should track by SUBJECT when caller is authenticated principal attempting invalid re-auth")
    void testTargetEntitySubject() {
        String subject = "user.badlogin";
        Instant now = Instant.now();

        RuleEvaluationResult lastRes = null;
        for (int i = 1; i <= 5; i++) {
            ApiEvent ev = createAuthEvent("10.0.0.1", subject, 401, now.minusSeconds(10 - i));
            lastRes = rule.evaluate(ev);
        }

        assertThat(lastRes).isNotNull();
        assertThat(lastRes.triggered()).isTrue();
        assertThat(lastRes.targetEntityType()).isEqualTo("SUBJECT");
        assertThat(lastRes.targetEntityValue()).isEqualTo(subject);
    }

    @Test
    @DisplayName("Should not trigger on single benign token expiration")
    void testSingleExpiredTokenDoesNotTrigger() {
        ApiEvent ev = createAuthEvent("192.168.1.99", "anonymous", 401, Instant.now());
        RuleEvaluationResult res = rule.evaluate(ev);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not count attempts outside sliding window")
    void testWindowExpiration() {
        String attackerIp = "192.168.1.52";
        Instant now = Instant.now();

        // 4 old attempts outside 120s window
        for (int i = 1; i <= 4; i++) {
            ApiEvent ev = createAuthEvent(attackerIp, "anonymous", 401, now.minusSeconds(200 + i));
            rule.evaluate(ev);
        }

        // 1 attempt in current window (total active: 1 < threshold 5)
        ApiEvent currentEv = createAuthEvent(attackerIp, "anonymous", 401, now);
        RuleEvaluationResult res = rule.evaluate(currentEv);

        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should deduplicate repeated deliveries of the same event ID")
    void testEventDeduplication() {
        String attackerIp = "192.168.1.53";
        Instant now = Instant.now();

        ApiEvent event = createAuthEvent(attackerIp, "anonymous", 401, now);

        // Evaluate same event 5 times
        for (int i = 0; i < 4; i++) {
            rule.evaluate(event);
        }
        RuleEvaluationResult res = rule.evaluate(event);

        // Distinct count is only 1, so should not trigger
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not evaluate role-deficient HTTP 403 Forbidden requests")
    void testRoleDeficient403Ignored() {
        ApiEvent ev403 = new ApiEvent(
            UUID.randomUUID(), "cid-403", Instant.now(), "192.168.1.54", "GET",
            "/api/v1/security/events", "/security/events", 403, 10,
            "alex.morgan", "ROLE_CUSTOMER", "cust-1", "test-agent", null, "FORBIDDEN_ATTEMPT",
            "SECURITY_EVENT", null, "INSUFFICIENT_ROLE", 50, 0
        );

        RuleEvaluationResult res = rule.evaluate(ev403);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore actuator endpoints")
    void testActuatorIgnored() {
        ApiEvent evActuator = createAuthEventWithUri("192.168.1.55", "anonymous", 401, Instant.now(), "/actuator/health");
        RuleEvaluationResult res = rule.evaluate(evActuator);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should return not triggered when rule is disabled")
    void testRuleDisabled() {
        RuleAuth01 disabledRule = new RuleAuth01(stateStore, false, 5, 120);
        ApiEvent ev = createAuthEvent("192.168.1.56", "anonymous", 401, Instant.now());
        assertThat(disabledRule.evaluate(ev).triggered()).isFalse();
    }

    private ApiEvent createAuthEvent(String sourceIp, String authSubject, int statusCode, Instant timestamp) {
        return createAuthEventWithUri(sourceIp, authSubject, statusCode, timestamp, "/api/v1/customers/profile");
    }

    private ApiEvent createAuthEventWithUri(String sourceIp, String authSubject, int statusCode, Instant timestamp, String uri) {
        return new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            sourceIp,
            "GET",
            uri,
            uri,
            statusCode,
            12,
            authSubject,
            "",
            "anonymous".equals(authSubject) ? "" : "cust-" + authSubject,
            "curl/7.68.0",
            null,
            statusCode == 401 ? "UNAUTHENTICATED_ACCESS" : "NONE",
            "CUSTOMER",
            null,
            statusCode == 401 ? "UNAUTHENTICATED" : null,
            120,
            0
        );
    }
}
