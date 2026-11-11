package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.DataSensitivityLevel;
import com.aegis.gateway.classification.SensitiveDataClassificationEngine;
import com.aegis.gateway.detection.correlation.CorrelationResult;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.RuleProbe01;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.detection.state.RedisDetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Data Leakage & BOLA Detection Engine Unit Tests")
class DataLeakageDetectionTest {

    private SensitiveDataClassificationEngine classificationEngine;
    private DetectionStateStore stateStore;
    private RuleBolaConfirmed01 ruleBolaConfirmed;
    private RuleDataLeak01 ruleDataLeak;
    private RuleBulkExtract01 ruleBulkExtract;
    private RuleBola02 ruleBola02;
    private DataExfiltrationCampaignCorrelator exfilCorrelator;

    private static final String ALEX_CUST_ID = "10000000-0000-4000-8000-000000000001";
    private static final String SAM_CUST_ID = "10000000-0000-4000-8000-000000000002";

    @BeforeEach
    void setUp() {
        classificationEngine = new SensitiveDataClassificationEngine(null);
        stateStore = new RedisDetectionStateStore(null);

        ruleBolaConfirmed = new RuleBolaConfirmed01(classificationEngine, true);
        ruleDataLeak = new RuleDataLeak01(classificationEngine, true);
        ruleBulkExtract = new RuleBulkExtract01(stateStore, classificationEngine, true, 3, 10, 20000, 120);
        ruleBola02 = new RuleBola02(stateStore, true, 2, 2, 180);
        exfilCorrelator = new DataExfiltrationCampaignCorrelator();
    }

    private ApiEvent createEvent(
            String method,
            String path,
            String routeTemplate,
            int statusCode,
            String customerId,
            String authSubject,
            String authRoles,
            String resourceType,
            String resourceId,
            long sizeBytes,
            int recordCount) {
        return new ApiEvent(
            UUID.randomUUID(),
            UUID.randomUUID().toString(),
            Instant.now(),
            "192.168.1.100",
            method,
            path,
            routeTemplate,
            statusCode,
            25L,
            authSubject != null ? authSubject : "anonymous",
            authRoles != null ? authRoles : "",
            customerId != null ? customerId : "",
            "Aegis-TestClient/1.0",
            "hash_123",
            "NONE",
            resourceType,
            resourceId,
            null,
            sizeBytes,
            recordCount
        );
    }

    @Test
    @DisplayName("RULE-BOLA-CONFIRMED-01: Benign same-owner access does not trigger")
    void testBolaConfirmedBenignAccess() {
        ApiEvent event = createEvent(
            "GET",
            "/api/v1/customers/" + ALEX_CUST_ID,
            "/api/v1/customers/{customerId}",
            200,
            ALEX_CUST_ID,
            "alex.morgan",
            "ROLE_CUSTOMER",
            "CUSTOMER",
            ALEX_CUST_ID,
            450L,
            1
        );

        RuleEvaluationResult result = ruleBolaConfirmed.evaluate(event);
        assertFalse(result.triggered(), "Legitimate same-owner access must not trigger BOLA confirmed");
    }

    @Test
    @DisplayName("RULE-BOLA-CONFIRMED-01: Confirmed cross-owner access triggers CRITICAL incident")
    void testBolaConfirmedCrossOwnerLeak() {
        ApiEvent event = createEvent(
            "GET",
            "/api/v1/customers/" + SAM_CUST_ID,
            "/api/v1/customers/{customerId}",
            200,
            ALEX_CUST_ID, // Alex accessing Sam's record
            "alex.morgan",
            "ROLE_CUSTOMER",
            "CUSTOMER",
            SAM_CUST_ID,
            680L,
            1
        );

        RuleEvaluationResult result = ruleBolaConfirmed.evaluate(event);
        assertTrue(result.triggered(), "Confirmed cross-owner access must trigger BOLA confirmed");
        assertEquals("RULE-BOLA-CONFIRMED-01", result.ruleId());
        assertEquals("CUSTOMER", result.targetEntityType());
        assertEquals(ALEX_CUST_ID, result.targetEntityValue());

        assertTrue(result.evidence().isPresent());
        DetectionEvidence ev = result.evidence().get();
        assertEquals("CRITICAL", ev.severity());
        assertTrue(ev.triggerCondition().contains(SAM_CUST_ID));
        assertTrue(ev.triggerCondition().contains("CONFIDENTIAL"));
    }

    @Test
    @DisplayName("RULE-BOLA-CONFIRMED-01: Security analyst privileged access is permitted")
    void testBolaConfirmedAnalystPermitted() {
        ApiEvent event = createEvent(
            "GET",
            "/api/v1/customers/" + SAM_CUST_ID,
            "/api/v1/customers/{customerId}",
            200,
            "analyst_id",
            "security.analyst",
            "SECURITY_ANALYST",
            "CUSTOMER",
            SAM_CUST_ID,
            680L,
            1
        );

        RuleEvaluationResult result = ruleBolaConfirmed.evaluate(event);
        assertFalse(result.triggered(), "Analyst access to customer records must not trigger BOLA alert");
    }

    @Test
    @DisplayName("RULE-DATA-LEAK-01: Anonymous caller accessing confidential data triggers alert")
    void testDataLeakAnonymousAccess() {
        ApiEvent event = createEvent(
            "GET",
            "/api/v1/customers/" + ALEX_CUST_ID + "/profile",
            "/api/v1/customers/{customerId}/profile",
            200,
            "",
            "anonymous",
            "",
            "CUSTOMER_PROFILE",
            ALEX_CUST_ID,
            550L,
            1
        );

        RuleEvaluationResult result = ruleDataLeak.evaluate(event);
        assertTrue(result.triggered(), "Anonymous access to confidential profile must trigger DATA-LEAK-01");
        assertEquals("RULE-DATA-LEAK-01", result.ruleId());
        assertEquals("HIGH", result.evidence().get().severity());
    }

    @Test
    @DisplayName("RULE-BULK-EXTRACT-01: Accessing >= 3 distinct customer resources triggers bulk extraction")
    void testBulkExtractionThreshold() {
        String attackerId = "attacker_cust_01";

        // Access 1: resource A
        ApiEvent e1 = createEvent("GET", "/api/v1/accounts/ACCT-001/balance", "/api/v1/accounts/{accountId}/balance", 200, attackerId, "user.one", "ROLE_CUSTOMER", "ACCOUNT_BALANCE", "ACCT-001", 300L, 1);
        assertFalse(ruleBulkExtract.evaluate(e1).triggered());

        // Access 2: resource B
        ApiEvent e2 = createEvent("GET", "/api/v1/accounts/ACCT-002/balance", "/api/v1/accounts/{accountId}/balance", 200, attackerId, "user.one", "ROLE_CUSTOMER", "ACCOUNT_BALANCE", "ACCT-002", 300L, 1);
        assertFalse(ruleBulkExtract.evaluate(e2).triggered());

        // Access 3: resource C -> Breaches distinct threshold (3)
        ApiEvent e3 = createEvent("GET", "/api/v1/accounts/ACCT-003/balance", "/api/v1/accounts/{accountId}/balance", 200, attackerId, "user.one", "ROLE_CUSTOMER", "ACCOUNT_BALANCE", "ACCT-003", 300L, 1);
        RuleEvaluationResult r3 = ruleBulkExtract.evaluate(e3);

        assertTrue(r3.triggered(), "Accessing 3 distinct sensitive resources must trigger BULK-EXTRACT-01");
        assertEquals("RULE-BULK-EXTRACT-01", r3.ruleId());
        assertEquals("HIGH", r3.evidence().get().severity());
        assertEquals(3, r3.evidence().get().distinctResources());
    }

    @Test
    @DisplayName("RULE-BOLA-02: BOLA denial followed by probing triggers campaign")
    void testBolaProbingCampaign() {
        String attackerId = "probing_cust_01";

        // Initial BOLA denial (403)
        stateStore.recordBolaAttempt(attackerId, UUID.randomUUID(), "CUST-001", Instant.now().minusSeconds(10));

        // Subsequent probe 1 (404)
        ApiEvent probe1 = createEvent("GET", "/api/v1/customers/CUST-002", "/api/v1/customers/{customerId}", 404, attackerId, "probe_user", "ROLE_CUSTOMER", "CUSTOMER", "CUST-002", 150L, 0);
        ruleBola02.evaluate(probe1);

        // Subsequent probe 2 (403)
        ApiEvent probe2 = createEvent("GET", "/api/v1/customers/CUST-003", "/api/v1/customers/{customerId}", 403, attackerId, "probe_user", "ROLE_CUSTOMER", "CUSTOMER", "CUST-003", 150L, 0);
        RuleEvaluationResult result = ruleBola02.evaluate(probe2);

        assertTrue(result.triggered(), "BOLA denial followed by probes on adjacent IDs must trigger BOLA-02");
        assertEquals("RULE-BOLA-02", result.ruleId());
        assertEquals("HIGH", result.evidence().get().severity());
    }

    @Test
    @DisplayName("DataExfiltrationCampaignCorrelator: Correlates multi-stage exfiltration into CRITICAL campaign")
    void testMultiStageExfiltrationCorrelation() {
        String actorId = "exfil_actor_99";
        UUID incidentId = UUID.randomUUID();

        // Stage 1: Active probing incident
        SecurityIncident activeIncident = new SecurityIncident(
            incidentId,
            "fp_exfil_1",
            RuleProbe01.RULE_ID,
            "1.0.0",
            "PROBING",
            "LOW",
            IncidentStatus.OPEN,
            "CUSTOMER",
            actorId,
            Instant.now().minusSeconds(60),
            Instant.now().minusSeconds(30),
            3,
            "Reconnaissance probing detected",
            Instant.now().minusSeconds(60),
            Instant.now()
        );

        DetectionEvidence stage1Evidence = new DetectionEvidence(
            UUID.randomUUID(),
            incidentId,
            RuleProbe01.RULE_ID,
            "1.0.0",
            Instant.now().minusSeconds(30),
            0.85,
            "LOW",
            "3 endpoint probes",
            3,
            120,
            2,
            "Probe evidence",
            List.of(UUID.randomUUID()),
            Instant.now()
        );

        // Stage 3: Incoming Data Leakage Evidence
        DetectionEvidence stage3Evidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            RuleBolaConfirmed01.RULE_ID,
            "1.0.0",
            Instant.now(),
            0.95,
            "CRITICAL",
            "Confirmed BOLA data leak",
            1,
            60,
            1,
            "Data extraction evidence",
            List.of(UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult leakResult = RuleEvaluationResult.triggered(
            RuleBolaConfirmed01.RULE_ID,
            "1.0.0",
            "CUSTOMER",
            actorId,
            stage3Evidence,
            "Confirmed BOLA leakage"
        );

        CorrelationResult corr = exfilCorrelator.evaluateCorrelation(
            leakResult,
            activeIncident,
            List.of(stage1Evidence)
        );

        assertTrue(corr.correlated(), "Multi-stage progression must correlate");
        assertEquals("DATA_EXFILTRATION_CAMPAIGN", corr.updatedThreatCategory());
        assertEquals("CRITICAL", corr.escalatedSeverity());
        assertTrue(corr.combinedConfidence() >= 0.95);
        assertTrue(corr.summary().contains("Multi-stage exfiltration campaign"));
    }
}

