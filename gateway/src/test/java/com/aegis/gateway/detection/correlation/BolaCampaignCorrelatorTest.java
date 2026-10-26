package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class BolaCampaignCorrelatorTest {

    private BolaCampaignCorrelator correlator;

    @BeforeEach
    void setUp() {
        correlator = new BolaCampaignCorrelator();
    }

    @Test
    @DisplayName("Should combine independent evidence confidences using Bayesian probability without overflow")
    void testBayesianConfidenceCombination() {
        double c1 = 0.80;
        double c2 = 0.80;
        double combined = BolaCampaignCorrelator.calculateBayesianConfidence(c1, c2);
        // 1 - (1 - 0.8)*(1 - 0.8) = 1 - 0.04 = 0.96
        assertThat(combined).isEqualTo(0.96);

        // High confidence capped safely at 0.99
        double cHigh1 = 0.95;
        double cHigh2 = 0.95;
        double combinedHigh = BolaCampaignCorrelator.calculateBayesianConfidence(cHigh1, cHigh2);
        assertThat(combinedHigh).isEqualTo(0.99);
    }

    @Test
    @DisplayName("Should correlate multi-resource attacks across 4+ distinct targets and escalate to CRITICAL BOLA_CAMPAIGN")
    void testCorrelateMultiResourceAttackEscalatesToCritical() {
        UUID incidentId = UUID.randomUUID();
        Instant now = Instant.now();

        SecurityIncident activeIncident = new SecurityIncident(
            incidentId,
            "fingerprint-1",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-attacker-1",
            now.minusSeconds(120),
            now.minusSeconds(60),
            3,
            "Initial BOLA attempt",
            now.minusSeconds(120),
            now.minusSeconds(60)
        );

        UUID ev1Id = UUID.randomUUID();
        UUID ev2Id = UUID.randomUUID();
        DetectionEvidence pastEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            incidentId,
            "RULE-BOLA-01",
            "1.0.0",
            now.minusSeconds(60),
            0.95,
            "HIGH",
            "observed >= 3",
            3,
            300,
            2,
            "{\"customerId\":\"cust-attacker-1\",\"distinctResources\":[target-1, target-2]}",
            List.of(ev1Id, ev2Id),
            now.minusSeconds(60)
        );

        UUID ev3Id = UUID.randomUUID();
        UUID ev4Id = UUID.randomUUID();
        DetectionEvidence newEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            now,
            0.95,
            "HIGH",
            "observed >= 2",
            2,
            300,
            2,
            "{\"customerId\":\"cust-attacker-1\",\"distinctResources\":[target-3, target-4]}",
            List.of(ev3Id, ev4Id),
            now
        );

        RuleEvaluationResult newResult = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-1",
            newEvidence,
            "Additional targets probed"
        );

        CorrelationResult corrResult = correlator.evaluateCorrelation(
            newResult,
            activeIncident,
            List.of(pastEvidence)
        );

        assertThat(corrResult.correlated()).isTrue();
        assertThat(corrResult.isDuplicate()).isFalse();
        assertThat(corrResult.updatedThreatCategory()).isEqualTo("BOLA_CAMPAIGN");
        assertThat(corrResult.escalatedSeverity()).isEqualTo("CRITICAL");
        assertThat(corrResult.combinedConfidence()).isGreaterThanOrEqualTo(0.98);
        assertThat(corrResult.distinctResourceCount()).isGreaterThanOrEqualTo(4);
        assertThat(corrResult.allContributingEventIds()).containsExactlyInAnyOrder(ev1Id, ev2Id, ev3Id, ev4Id);
    }

    @Test
    @DisplayName("Anti-Affinity Rule: Should NOT correlate evidence from a different customer even if same IP or rule")
    void testAntiAffinitySharedIpDifferentCustomerDoesNotCorrelate() {
        SecurityIncident activeIncident = new SecurityIncident(
            UUID.randomUUID(),
            "fingerprint-1",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-company-user-A",
            Instant.now(),
            Instant.now(),
            3,
            "BOLA on customer A",
            Instant.now(),
            Instant.now()
        );

        DetectionEvidence newEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "observed >= 3",
            3,
            300,
            2,
            "{\"customerId\":\"cust-company-user-B\"}",
            List.of(UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult newResult = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-company-user-B", // Different customer identity!
            newEvidence,
            "BOLA on customer B"
        );

        CorrelationResult corrResult = correlator.evaluateCorrelation(
            newResult,
            activeIncident,
            List.of()
        );

        // Anti-affinity MUST reject correlation
        assertThat(corrResult.correlated()).isFalse();
    }

    @Test
    @DisplayName("Idempotency: Re-delivered evidence with identical event IDs should NOT inflate count or confidence")
    void testIdempotentDuplicateEvidenceDoesNotInflateCountsOrConfidence() {
        UUID incidentId = UUID.randomUUID();
        UUID sharedEventId1 = UUID.randomUUID();
        UUID sharedEventId2 = UUID.randomUUID();

        SecurityIncident activeIncident = new SecurityIncident(
            incidentId,
            "fingerprint-1",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-attacker-1",
            Instant.now().minusSeconds(30),
            Instant.now(),
            2,
            "Initial",
            Instant.now().minusSeconds(30),
            Instant.now()
        );

        DetectionEvidence pastEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            incidentId,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now().minusSeconds(30),
            0.95,
            "HIGH",
            "test",
            2,
            300,
            2,
            "{\"distinctResources\":[r1, r2]}",
            List.of(sharedEventId1, sharedEventId2),
            Instant.now().minusSeconds(30)
        );

        // Redelivered evidence containing the exact same event IDs
        DetectionEvidence duplicateEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "test",
            2,
            300,
            2,
            "{\"distinctResources\":[r1, r2]}",
            List.of(sharedEventId1, sharedEventId2),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-1",
            duplicateEvidence,
            "Redelivered trigger"
        );

        CorrelationResult corrResult = correlator.evaluateCorrelation(
            result,
            activeIncident,
            List.of(pastEvidence)
        );

        assertThat(corrResult.correlated()).isTrue();
        assertThat(corrResult.isDuplicate()).isTrue();
        assertThat(corrResult.totalObservedCount()).isEqualTo(2); // Not inflated to 4
        assertThat(corrResult.allContributingEventIds()).hasSize(2);
    }
}
