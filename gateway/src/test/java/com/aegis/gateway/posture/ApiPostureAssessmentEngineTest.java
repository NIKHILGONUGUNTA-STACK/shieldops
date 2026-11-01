package com.aegis.gateway.posture;

import com.aegis.gateway.discovery.dto.*;
import com.aegis.gateway.posture.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiPostureAssessmentEngineTest {

    private ApiPostureAssessmentEngine engine;

    @BeforeEach
    void setUp() {
        engine = new ApiPostureAssessmentEngine();
    }

    @Test
    @DisplayName("Throws exception if intelligence dossier is null")
    void throwsOnNullIntel() {
        assertThatThrownBy(() -> engine.assess(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Guaranteed Defensive Invariant: confirmedVulnerability is always FALSE")
    void confirmsVulnerabilityIsAlwaysFalse() {
        EndpointIntelligenceResponse intel = createMockIntel(
            "ep_1", "POST", "/api/v1/transfers", "transaction-service", 100,
            "MATCHED", 0, 0, Collections.emptyList()
        );

        EndpointPostureResponse response = engine.assess(intel);
        assertThat(response.confirmedVulnerability()).isFalse();
    }

    @Test
    @DisplayName("Exposure Dimension: VERIFIED when MATCHED, FINDING when OBSERVED_UNDOCUMENTED, UNKNOWN when 0 requests")
    void evaluatesExposureDimension() {
        // MATCHED -> VERIFIED
        EndpointIntelligenceResponse matched = createMockIntel(
            "ep_1", "GET", "/api/v1/customers/{customerId}", "customer-service", 50,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respMatched = engine.assess(matched);
        assertThat(respMatched.dimensions().get("EXPOSURE").status()).isEqualTo(DimensionStatus.VERIFIED);

        // OBSERVED_UNDOCUMENTED -> FINDING (Shadow API)
        EndpointIntelligenceResponse shadow = createMockIntel(
            "ep_2", "POST", "/api/v1/internal/debug", "customer-service", 20,
            "OBSERVED_UNDOCUMENTED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respShadow = engine.assess(shadow);
        assertThat(respShadow.dimensions().get("EXPOSURE").status()).isEqualTo(DimensionStatus.FINDING);
        assertThat(respShadow.dimensions().get("EXPOSURE").summary()).contains("Shadow API Exposure");

        // 0 requests -> UNKNOWN
        EndpointIntelligenceResponse unobserved = createMockIntel(
            "ep_3", "GET", "/api/v1/dormant", "customer-service", 0,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respUnobserved = engine.assess(unobserved);
        assertThat(respUnobserved.dimensions().get("EXPOSURE").status()).isEqualTo(DimensionStatus.UNKNOWN);
    }

    @Test
    @DisplayName("Authentication Dimension: VERIFIED on Gateway-protected routes and public actuator; FINDING on elevated 401s")
    void evaluatesAuthenticationDimension() {
        // Protected route with clean auth -> VERIFIED
        EndpointIntelligenceResponse protectedClean = createMockIntel(
            "ep_1", "GET", "/api/v1/customers/{customerId}", "customer-service", 100,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respProtected = engine.assess(protectedClean);
        assertThat(respProtected.dimensions().get("AUTHENTICATION").status()).isEqualTo(DimensionStatus.VERIFIED);
        assertThat(respProtected.dimensions().get("AUTHENTICATION").summary()).contains("Perimeter authentication enforced");

        // Public actuator route -> VERIFIED (permitAll)
        EndpointIntelligenceResponse publicActuator = createMockIntel(
            "ep_2", "GET", "/actuator/health", "gateway-service", 200,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respActuator = engine.assess(publicActuator);
        assertThat(respActuator.dimensions().get("AUTHENTICATION").status()).isEqualTo(DimensionStatus.VERIFIED);
        assertThat(respActuator.dimensions().get("AUTHENTICATION").summary()).contains("Public endpoint by design");

        // Elevated 401s -> FINDING
        EndpointIntelligenceResponse elevated401 = createMockIntel(
            "ep_3", "GET", "/api/v1/customers/{customerId}", "customer-service", 50,
            "MATCHED", 15, 0, Collections.emptyList()
        );
        EndpointPostureResponse respElevated = engine.assess(elevated401);
        assertThat(respElevated.dimensions().get("AUTHENTICATION").status()).isEqualTo(DimensionStatus.FINDING);
        assertThat(respElevated.dimensions().get("AUTHENTICATION").summary()).contains("Elevated authentication failures");
    }

    @Test
    @DisplayName("Authorization Dimension: FINDING on linked BOLA incident; UNKNOWN on normal status without object-level policy proof")
    void evaluatesAuthorizationDimension() {
        // Linked BOLA incident -> FINDING
        EndpointLinkedIncident bolaIncident = new EndpointLinkedIncident(
            UUID.randomUUID(), "RULE-BOLA-01", "BOLA", "HIGH", "OPEN", "BOLA Detected", Instant.now()
        );
        EndpointIntelligenceResponse bolaIntel = createMockIntel(
            "ep_1", "GET", "/api/v1/accounts/{accountId}", "account-service", 80,
            "MATCHED", 0, 1, List.of(bolaIncident)
        );
        EndpointPostureResponse respBola = engine.assess(bolaIntel);
        assertThat(respBola.dimensions().get("AUTHORIZATION").status()).isEqualTo(DimensionStatus.FINDING);
        assertThat(respBola.dimensions().get("AUTHORIZATION").summary()).contains("Broken Object Level Authorization");

        // Clean telemetry -> UNKNOWN (strict invariant: 200 is not proof of authorization, gateway cannot verify microservice data ownership)
        EndpointIntelligenceResponse cleanIntel = createMockIntel(
            "ep_2", "GET", "/api/v1/accounts/{accountId}", "account-service", 80,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respClean = engine.assess(cleanIntel);
        assertThat(respClean.dimensions().get("AUTHORIZATION").status()).isEqualTo(DimensionStatus.UNKNOWN);
        assertThat(respClean.dimensions().get("AUTHORIZATION").limitations()).contains("cannot verify application-layer data ownership validation on successful 200 responses");
    }

    @Test
    @DisplayName("Data Sensitivity Dimension: strictly UNKNOWN; keyword inference (customer, account, profile) is prohibited")
    void evaluatesDataSensitivityDimensionStrictlyUnknown() {
        // Route contains customer, account, profile -> MUST STILL BE UNKNOWN!
        EndpointIntelligenceResponse intel = createMockIntel(
            "ep_1", "GET", "/api/v1/customers/{customerId}/profile/accounts", "customer-service", 100,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse response = engine.assess(intel);
        assertThat(response.dimensions().get("DATA_SENSITIVITY").status()).isEqualTo(DimensionStatus.UNKNOWN);
        assertThat(response.dimensions().get("DATA_SENSITIVITY").summary()).contains("No explicit data sensitivity or PII classification metadata");
        assertThat(response.dimensions().get("DATA_SENSITIVITY").limitations()).contains("Automatic keyword inference");
    }

    @Test
    @DisplayName("Behavioral Dimension: VERIFIED on clean traffic (>= 5 requests, 0 incidents); FINDING on linked incidents; UNKNOWN on low traffic")
    void evaluatesBehavioralDimension() {
        // Clean traffic (>=5 requests) -> VERIFIED
        EndpointIntelligenceResponse clean = createMockIntel(
            "ep_1", "GET", "/api/v1/beneficiaries", "customer-service", 50,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respClean = engine.assess(clean);
        assertThat(respClean.dimensions().get("BEHAVIORAL").status()).isEqualTo(DimensionStatus.VERIFIED);

        // High request count by itself is NOT automatically malicious
        EndpointIntelligenceResponse highVolume = createMockIntel(
            "ep_2", "GET", "/api/v1/beneficiaries", "customer-service", 50000,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respHigh = engine.assess(highVolume);
        assertThat(respHigh.dimensions().get("BEHAVIORAL").status()).isEqualTo(DimensionStatus.VERIFIED);

        // Low volume (<5 requests) -> UNKNOWN
        EndpointIntelligenceResponse lowVolume = createMockIntel(
            "ep_3", "GET", "/api/v1/beneficiaries", "customer-service", 3,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respLow = engine.assess(lowVolume);
        assertThat(respLow.dimensions().get("BEHAVIORAL").status()).isEqualTo(DimensionStatus.UNKNOWN);

        // Correlated incidents -> FINDING
        EndpointLinkedIncident incident = new EndpointLinkedIncident(
            UUID.randomUUID(), "RULE-RATE-01", "RATE_LIMIT", "MEDIUM", "INVESTIGATING", "Rate Limit Anomaly", Instant.now()
        );
        EndpointIntelligenceResponse withIncident = createMockIntel(
            "ep_4", "GET", "/api/v1/beneficiaries", "customer-service", 100,
            "MATCHED", 0, 1, List.of(incident)
        );
        EndpointPostureResponse respIncident = engine.assess(withIncident);
        assertThat(respIncident.dimensions().get("BEHAVIORAL").status()).isEqualTo(DimensionStatus.FINDING);
    }

    @Test
    @DisplayName("Overall Categorical Posture: ATTENTION_REQUIRED when any finding exists, INSUFFICIENT_EVIDENCE when >=3 unknown and 0 findings")
    void evaluatesOverallCategoricalPosture() {
        // Shadow API has findings -> ATTENTION_REQUIRED
        EndpointIntelligenceResponse shadow = createMockIntel(
            "ep_1", "POST", "/api/v1/shadow", "customer-service", 50,
            "OBSERVED_UNDOCUMENTED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respShadow = engine.assess(shadow);
        assertThat(respShadow.overallPosture()).isEqualTo(OverallPosture.ATTENTION_REQUIRED);
        assertThat(respShadow.totalFindingsCount()).isGreaterThan(0);

        // Matched endpoint with clean traffic:
        // Exposure=VERIFIED, Auth=VERIFIED, Authz=UNKNOWN, DataSensitivity=UNKNOWN, Behavioral=VERIFIED, Spec=VERIFIED
        // Verified = 4, Unknown = 2, Finding = 0 -> ADEQUATE!
        EndpointIntelligenceResponse clean = createMockIntel(
            "ep_2", "GET", "/api/v1/customers/{customerId}", "customer-service", 50,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respClean = engine.assess(clean);
        assertThat(respClean.overallPosture()).isEqualTo(OverallPosture.ADEQUATE);
        assertThat(respClean.evidenceCoveragePercentage()).isGreaterThanOrEqualTo(66.0);

        // Unobserved endpoint (0 requests):
        // Exposure=UNKNOWN, Authz=UNKNOWN, DataSensitivity=UNKNOWN, Behavioral=UNKNOWN -> Unknown >= 3 -> INSUFFICIENT_EVIDENCE
        EndpointIntelligenceResponse unobserved = createMockIntel(
            "ep_3", "GET", "/api/v1/customers/{customerId}", "customer-service", 0,
            "MATCHED", 0, 0, Collections.emptyList()
        );
        EndpointPostureResponse respUnobserved = engine.assess(unobserved);
        assertThat(respUnobserved.overallPosture()).isEqualTo(OverallPosture.INSUFFICIENT_EVIDENCE);
    }

    @Test
    @DisplayName("Assessment output is deterministic for identical input")
    void isDeterministicForIdenticalInput() {
        EndpointIntelligenceResponse intel = createMockIntel(
            "ep_det", "GET", "/api/v1/customers/{customerId}", "customer-service", 50,
            "MATCHED", 0, 0, Collections.emptyList()
        );

        EndpointPostureResponse resp1 = engine.assess(intel);
        EndpointPostureResponse resp2 = engine.assess(intel);

        assertThat(resp1.overallPosture()).isEqualTo(resp2.overallPosture());
        assertThat(resp1.evidenceCoveragePercentage()).isEqualTo(resp2.evidenceCoveragePercentage());
        assertThat(resp1.totalFindingsCount()).isEqualTo(resp2.totalFindingsCount());
        assertThat(resp1.dimensions().keySet()).isEqualTo(resp2.dimensions().keySet());
        for (String dimKey : resp1.dimensions().keySet()) {
            assertThat(resp1.dimensions().get(dimKey).status())
                .isEqualTo(resp2.dimensions().get(dimKey).status());
        }
    }

    // Helper method to create mock EndpointIntelligenceResponse
    private EndpointIntelligenceResponse createMockIntel(
            String id,
            String method,
            String route,
            String service,
            long totalRequests,
            String reconStatus,
            long authFailures,
            long anomalies,
            List<EndpointLinkedIncident> incidents) {

        EndpointSpecMetadata spec = "MATCHED".equalsIgnoreCase(reconStatus)
            ? new EndpointSpecMetadata(UUID.randomUUID(), service + " API", "1.0.0", 1, "op_" + id, "Summary", "Description", "tag1", false)
            : null;

        EndpointReconciliationStatus recon = new EndpointReconciliationStatus(
            reconStatus, "Explanation", "HIGH", "Direct match"
        );

        EndpointPrioritizationDetail prio = new EndpointPrioritizationDetail(
            "LOW", 10, "v1.0.0", Collections.emptyList(), false
        );

        Map<String, Long> dist = new HashMap<>();
        dist.put("2xx", Math.max(0, totalRequests - authFailures));
        dist.put("4xx", authFailures);
        dist.put("5xx", 0L);

        return new EndpointIntelligenceResponse(
            id,
            method,
            route,
            service,
            Instant.now().minusSeconds(86400),
            Instant.now(),
            totalRequests,
            25.0,
            dist,
            List.of(200),
            spec,
            recon,
            prio,
            authFailures,
            anomalies,
            incidents
        );
    }
}
