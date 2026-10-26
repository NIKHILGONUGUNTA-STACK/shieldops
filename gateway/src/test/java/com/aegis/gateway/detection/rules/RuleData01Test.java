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

class RuleData01Test {

    private InMemoryDetectionStateStore stateStore;
    private RuleData01 rule;

    @BeforeEach
    void setUp() {
        stateStore = new InMemoryDetectionStateStore();
        // singleBytes: 50000, singleRecords: 25, cumBytes: 100000, cumRecords: 40, window: 120
        rule = new RuleData01(stateStore, true, 50000L, 25, 100000L, 40, 120);
    }

    @Test
    @DisplayName("Should trigger when single response exceeds byte threshold")
    void testSingleResponseByteThresholdTrigger() {
        String customerId = "cust-exfil-01";
        ApiEvent ev = createDataEvent(customerId, 1, 60000L, 200, Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-DATA-01");
        assertThat(res.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(res.targetEntityValue()).isEqualTo(customerId);

        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("MEDIUM");
        assertThat(evidence.confidenceScore()).isEqualTo(0.85);
    }

    @Test
    @DisplayName("Should trigger when single response exceeds record count threshold")
    void testSingleResponseRecordThresholdTrigger() {
        String customerId = "cust-exfil-02";
        ApiEvent ev = createDataEvent(customerId, 30, 15000L, 200, Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);

        assertThat(res.triggered()).isTrue();
        assertThat(res.ruleId()).isEqualTo("RULE-DATA-01");
        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.observedCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should trigger when cumulative records exceed threshold in window")
    void testCumulativeRecordThresholdTrigger() {
        String customerId = "cust-exfil-03";
        Instant now = Instant.now();

        // 4 calls returning 10 records each (total 40 records >= threshold 40)
        RuleEvaluationResult res = null;
        for (int i = 1; i <= 4; i++) {
            ApiEvent ev = createDataEvent(customerId, 10, 5000L, 200, now.minusSeconds(20 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.observedCount()).isEqualTo(4);
    }

    @Test
    @DisplayName("Should trigger and escalate to HIGH severity on massive cumulative volume")
    void testMassiveExfiltrationEscalation() {
        String customerId = "cust-exfil-04";
        Instant now = Instant.now();

        // 3 calls of 30 records and 80,000 bytes each (total 90 records >= 80 and 240,000 bytes >= 200,000)
        RuleEvaluationResult res = null;
        for (int i = 1; i <= 3; i++) {
            ApiEvent ev = createDataEvent(customerId, 30, 80000L, 200, now.minusSeconds(15 - i));
            res = rule.evaluate(ev);
        }

        assertThat(res).isNotNull();
        assertThat(res.triggered()).isTrue();
        DetectionEvidence evidence = res.evidence().get();
        assertThat(evidence.severity()).isEqualTo("HIGH");
        assertThat(evidence.confidenceScore()).isEqualTo(0.92);
    }

    @Test
    @DisplayName("Should not trigger on normal single profile read (1 record, small bytes)")
    void testNormalProfileAccessDoesNotTrigger() {
        String customerId = "cust-normal-01";
        ApiEvent ev = createDataEvent(customerId, 1, 450L, 200, Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should not trigger on normal account list (2 records, 1000 bytes)")
    void testNormalAccountsListDoesNotTrigger() {
        String customerId = "cust-normal-02";
        ApiEvent ev = createDataEvent(customerId, 2, 1050L, 200, Instant.now());

        RuleEvaluationResult res = rule.evaluate(ev);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore unauthenticated or anonymous callers")
    void testAnonymousCallerIgnored() {
        ApiEvent ev = createDataEvent("", 100, 200000L, 200, Instant.now());
        RuleEvaluationResult res = rule.evaluate(ev);
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should ignore non-200 responses")
    void testNon200Ignored() {
        String customerId = "cust-exfil-05";
        ApiEvent ev403 = createDataEvent(customerId, 50, 100000L, 403, Instant.now());
        assertThat(rule.evaluate(ev403).triggered()).isFalse();

        ApiEvent ev404 = createDataEvent(customerId, 50, 100000L, 404, Instant.now());
        assertThat(rule.evaluate(ev404).triggered()).isFalse();
    }

    @Test
    @DisplayName("Should deduplicate repeated deliveries of the same event ID")
    void testEventDeduplication() {
        String customerId = "cust-exfil-06";
        Instant now = Instant.now();

        // 1 event with 10 records and 10000 bytes
        ApiEvent ev = createDataEvent(customerId, 10, 10000L, 200, now);

        // Evaluate 5 times with exact same event ID
        for (int i = 0; i < 4; i++) {
            rule.evaluate(ev);
        }
        RuleEvaluationResult res = rule.evaluate(ev);

        // Deduplicated cumulative count remains 10 (below threshold 40)
        assertThat(res.triggered()).isFalse();
    }

    @Test
    @DisplayName("Should return not triggered when rule is disabled")
    void testRuleDisabled() {
        RuleData01 disabled = new RuleData01(stateStore, false, 50000L, 25, 100000L, 40, 120);
        ApiEvent ev = createDataEvent("cust-1", 100, 200000L, 200, Instant.now());
        assertThat(disabled.evaluate(ev).triggered()).isFalse();
    }

    private ApiEvent createDataEvent(String customerId, int recordCount, long responseSizeBytes, int statusCode, Instant timestamp) {
        return new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID().toString().substring(0, 8),
            timestamp,
            "192.168.1.100",
            "GET",
            "/api/v1/accounts?customerId=" + customerId,
            "/accounts",
            statusCode,
            25,
            "sub-" + customerId,
            "ROLE_CUSTOMER",
            customerId,
            "Mozilla/5.0",
            null,
            "NONE",
            "ACCOUNT_LIST",
            customerId,
            null,
            responseSizeBytes,
            recordCount
        );
    }
}
