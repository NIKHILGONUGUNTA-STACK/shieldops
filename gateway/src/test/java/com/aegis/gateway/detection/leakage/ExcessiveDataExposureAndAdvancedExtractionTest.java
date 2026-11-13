package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.*;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.detection.state.RedisDetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("Phase 7.2.4.4 — Excessive Data Exposure & Advanced Extraction Detection Tests")
class ExcessiveDataExposureAndAdvancedExtractionTest {

    private SensitiveDataClassificationEngine classificationEngine;
    private DetectionStateStore stateStore;
    private RuleExcessiveDataExposure01 exposureRule;
    private RuleAdvancedExtraction01 extractionRule;

    private final UUID customerAlex = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private final UUID accountAlex1 = UUID.fromString("20000000-0000-4000-8000-000000000001");
    private final UUID accountSam1 = UUID.fromString("20000000-0000-4000-8000-000000000003");

    @BeforeEach
    void setUp() {
        classificationEngine = new SensitiveDataClassificationEngine(null);
        StringRedisTemplate mockRedis = mock(StringRedisTemplate.class);
        stateStore = new RedisDetectionStateStore(mockRedis);

        exposureRule = new RuleExcessiveDataExposure01(classificationEngine, true);
        extractionRule = new RuleAdvancedExtraction01(
            stateStore, classificationEngine, true,
            120, 600, 5, 2, 2, 3, 15, 50000L
        );
    }

    // =========================================================================
    // 1. RULE-EXCESSIVE-EXPOSURE-01 Tests
    // =========================================================================

    @Test
    @DisplayName("Exposure: RESTRICTED field exposed to non-admin triggers CRITICAL incident")
    void testRestrictedFieldExposureTriggersCritical() {
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(), "CORR-01", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/" + customerAlex + "/profile", "/api/v1/customers/{customerId}/profile",
            200, 15L, "alex.morgan", "ROLE_CUSTOMER", customerAlex.toString(), "Mozilla/5.0",
            null, "NONE", "CUSTOMER_PROFILE", customerAlex.toString(), null, 350L, 1,
            "id,customerNumber,email,access_token", null, null
        );

        RuleEvaluationResult result = exposureRule.evaluate(event);

        assertThat(result.triggered()).isTrue();
        assertThat(result.evidence()).isPresent();
        assertThat(result.evidence().get().severity()).isEqualTo("CRITICAL");
        assertThat(result.evidence().get().triggerCondition()).contains("RESTRICTED_FIELD_EXPOSURE");
    }

    @Test
    @DisplayName("Exposure: Sensitive fields returned to unauthenticated caller triggers CRITICAL")
    void testUnauthenticatedSensitiveExposure() {
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(), "CORR-02", Instant.now(), "198.51.100.5", "GET",
            "/api/v1/customers/" + customerAlex + "/profile", "/api/v1/customers/{customerId}/profile",
            200, 20L, "anonymous", "", "", "curl/7.88",
            null, "NONE", "CUSTOMER_PROFILE", customerAlex.toString(), null, 420L, 1,
            "id,customerNumber,email,firstName", null, null
        );

        RuleEvaluationResult result = exposureRule.evaluate(event);

        assertThat(result.triggered()).isTrue();
        assertThat(result.evidence()).isPresent();
        assertThat(result.evidence().get().severity()).isEqualTo("CRITICAL");
        assertThat(result.evidence().get().triggerCondition()).contains("UNAUTHENTICATED_SENSITIVE_EXPOSURE");
    }

    @Test
    @DisplayName("Exposure: Legitimate authorized owner accessing declared confidential fields is BENIGN")
    void testAuthorizedOwnerAccessIsBenign() {
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(), "CORR-03", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/customers/" + customerAlex + "/profile", "/api/v1/customers/{customerId}/profile",
            200, 12L, "alex.morgan", "ROLE_CUSTOMER", customerAlex.toString(), "Mozilla/5.0",
            null, "NONE", "CUSTOMER_PROFILE", customerAlex.toString(), null, 250L, 1,
            "id,customerNumber,email,firstName,lastName,countryCode,status", null, null
        );

        RuleEvaluationResult result = exposureRule.evaluate(event);

        assertThat(result.triggered()).isFalse();
    }

    @Test
    @DisplayName("Exposure: Missing observedFields metadata does NOT trigger false alarm")
    void testMissingFieldMetadataIsNonBlocking() {
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(), "CORR-04", Instant.now(), "10.0.0.1", "GET",
            "/api/v1/accounts/" + accountAlex1, "/api/v1/accounts/{id}",
            200, 10L, "alex.morgan", "ROLE_CUSTOMER", customerAlex.toString(), "Mozilla/5.0",
            null, "NONE", "ACCOUNT", accountAlex1.toString(), null, 200L, 1,
            null, null, null
        );

        RuleEvaluationResult result = exposureRule.evaluate(event);

        assertThat(result.triggered()).isFalse();
    }

    // =========================================================================
    // 2. RULE-ADV-EXTRACT-01 Tests
    // =========================================================================

    @Test
    @DisplayName("Advanced Extraction: Automated pagination harvesting across >= 3 pages triggers PAGINATION_EXTRACTION")
    void testPaginationHarvestingDetected() {
        Instant now = Instant.now();

        // 3 consecutive page accesses by same entity within short window
        for (int p = 0; p < 3; p++) {
            ApiEvent event = new ApiEvent(
                UUID.randomUUID(), "CORR-PAG-" + p, now.plusSeconds(p * 5), "10.0.0.1", "GET",
                "/api/v1/accounts", "/api/v1/accounts",
                200, 15L, "harvester.user", "ROLE_CUSTOMER", "harvester-01", "Scraper/1.0",
                null, "NONE", "ACCOUNT_LIST", "all", null, 800L, 4,
                "id,accountNumber,balance", p, 4
            );
            RuleEvaluationResult res = extractionRule.evaluate(event);
            if (p < 2) {
                assertThat(res.triggered()).isFalse();
            } else {
                assertThat(res.triggered()).isTrue();
                assertThat(res.evidence()).isPresent();
                assertThat(res.evidence().get().triggerCondition()).contains("PAGINATION_EXTRACTION");
            }
        }
    }

    @Test
    @DisplayName("Advanced Extraction: Multi-resource extraction across Customer and Account entities")
    void testMultiResourceExtractionDetected() {
        Instant now = Instant.now();
        String attacker = "multi-attacker";

        // Access 1: Customer Profile
        ApiEvent ev1 = new ApiEvent(
            UUID.randomUUID(), "CORR-M1", now, "10.0.0.5", "GET",
            "/api/v1/customers/c1/profile", "/api/v1/customers/{customerId}/profile",
            200, 10L, attacker, "ROLE_CUSTOMER", attacker, "Python/3.14",
            null, "NONE", "CUSTOMER_PROFILE", "c1", null, 300L, 1,
            "id,email", null, null
        );
        extractionRule.evaluate(ev1);

        // Access 2: Account 1
        ApiEvent ev2 = new ApiEvent(
            UUID.randomUUID(), "CORR-M2", now.plusSeconds(2), "10.0.0.5", "GET",
            "/api/v1/accounts/a1", "/api/v1/accounts/{id}",
            200, 10L, attacker, "ROLE_CUSTOMER", attacker, "Python/3.14",
            null, "NONE", "ACCOUNT", "a1", null, 300L, 1,
            "id,balance", null, null
        );
        extractionRule.evaluate(ev2);

        // Access 3: Account 2
        ApiEvent ev3 = new ApiEvent(
            UUID.randomUUID(), "CORR-M3", now.plusSeconds(4), "10.0.0.5", "GET",
            "/api/v1/accounts/a2", "/api/v1/accounts/{id}",
            200, 10L, attacker, "ROLE_CUSTOMER", attacker, "Python/3.14",
            null, "NONE", "ACCOUNT", "a2", null, 300L, 1,
            "id,balance", null, null
        );
        RuleEvaluationResult res = extractionRule.evaluate(ev3);

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence()).isPresent();
        assertThat(res.evidence().get().triggerCondition()).contains("MULTI_RESOURCE_EXTRACTION");
    }

    @Test
    @DisplayName("Advanced Extraction: Distributed extraction across multiple sessions for same customer")
    void testDistributedExtractionDetected() {
        Instant now = Instant.now();
        String customerId = "compromised-cust";

        // Session 1 accesses resource 1
        extractionRule.evaluate(new ApiEvent(
            UUID.randomUUID(), "CORR-D1", now, "192.168.1.10", "GET",
            "/api/v1/accounts/acct-01", "/api/v1/accounts/{id}",
            200, 12L, "session-token-alpha", "ROLE_CUSTOMER", customerId, "MobileApp/1.0",
            null, "NONE", "ACCOUNT", "acct-01", null, 400L, 1,
            "id,balance", null, null
        ));

        // Session 2 accesses resource 2
        extractionRule.evaluate(new ApiEvent(
            UUID.randomUUID(), "CORR-D2", now.plusSeconds(3), "192.168.1.20", "GET",
            "/api/v1/accounts/acct-02", "/api/v1/accounts/{id}",
            200, 12L, "session-token-beta", "ROLE_CUSTOMER", customerId, "Browser/2.0",
            null, "NONE", "ACCOUNT", "acct-02", null, 400L, 1,
            "id,balance", null, null
        ));

        // Session 2 accesses resource 3
        RuleEvaluationResult res = extractionRule.evaluate(new ApiEvent(
            UUID.randomUUID(), "CORR-D3", now.plusSeconds(6), "192.168.1.20", "GET",
            "/api/v1/accounts/acct-03", "/api/v1/accounts/{id}",
            200, 12L, "session-token-beta", "ROLE_CUSTOMER", customerId, "Browser/2.0",
            null, "NONE", "ACCOUNT", "acct-03", null, 400L, 1,
            "id,balance", null, null
        ));

        assertThat(res.triggered()).isTrue();
        assertThat(res.evidence()).isPresent();
        assertThat(res.evidence().get().triggerCondition()).contains("DISTRIBUTED_EXTRACTION");
    }

    @Test
    @DisplayName("Advanced Extraction: Low-and-slow extraction over 600s window")
    void testLowAndSlowExtractionDetected() {
        Instant baseTime = Instant.now().minusSeconds(500);
        String stealthAttacker = "stealth-crawler";

        // Ingest 5 distinct resources spaced 90s apart (never >= 3 within any single 120s window)
        for (int i = 0; i < 5; i++) {
            ApiEvent ev = new ApiEvent(
                UUID.randomUUID(), "CORR-SLOW-" + i, baseTime.plusSeconds(i * 90), "10.0.0.100", "GET",
                "/api/v1/accounts/target-" + i, "/api/v1/accounts/{id}",
                200, 10L, stealthAttacker, "ROLE_CUSTOMER", stealthAttacker, "Curl/8.0",
                null, "NONE", "ACCOUNT", "target-" + i, null, 250L, 1,
                "id,balance", null, null
            );
            RuleEvaluationResult res = extractionRule.evaluate(ev);
            if (i < 4) {
                assertThat(res.triggered()).isFalse();
            } else {
                assertThat(res.triggered()).isTrue();
                assertThat(res.evidence()).isPresent();
                assertThat(res.evidence().get().triggerCondition()).contains("LOW_AND_SLOW_EXTRACTION");
            }
        }
    }
}
