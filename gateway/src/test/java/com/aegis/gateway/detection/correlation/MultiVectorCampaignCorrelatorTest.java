package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.RuleBola01;
import com.aegis.gateway.detection.rules.RuleData01;
import com.aegis.gateway.detection.rules.RuleProbe01;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class MultiVectorCampaignCorrelatorTest {

    private MultiVectorCampaignCorrelator correlator;

    @BeforeEach
    void setUp() {
        correlator = new MultiVectorCampaignCorrelator();
    }

    @Test
    @DisplayName("Should combine independent evidence heuristic confidences without exceeding 0.99 cap")
    void testHeuristicConfidenceCombination() {
        double c1 = 0.85;
        double c2 = 0.85;
        double combined = MultiVectorCampaignCorrelator.calculateCombinedConfidence(c1, c2);
        // 1 - (1 - 0.85)*(1 - 0.85) = 1 - 0.0225 = 0.9775 -> 0.98
        assertThat(combined).isEqualTo(0.98);

        // High confidence capped safely at 0.99
        double combinedHigh = MultiVectorCampaignCorrelator.calculateCombinedConfidence(0.95, 0.95);
        assertThat(combinedHigh).isEqualTo(0.99);
    }

    @Test
    @DisplayName("Should correlate Multi-Vector progression: Probe -> BOLA -> Data Exfiltration into COMPLEX_INTRUSION")
    void testMultiVectorCampaignProgression() {
        UUID incidentId = UUID.randomUUID();
        Instant now = Instant.now();
        String customerId = "cust-attacker-mv";

        // Step 1: Active incident was created by RULE-PROBE-01
        SecurityIncident activeIncident = new SecurityIncident(
            incidentId,
            "fp-mv-01",
            RuleProbe01.RULE_ID,
            "1.0.0",
            "RECON_PROBE",
            "MEDIUM",
            IncidentStatus.OPEN,
            "CUSTOMER",
            customerId,
            now.minusSeconds(180),
            now.minusSeconds(60),
            4,
            "Suspicious probing and validation failures detected",
            now.minusSeconds(180),
            now.minusSeconds(60)
        );

        UUID probeEvId = UUID.randomUUID();
        DetectionEvidence pastEvidence = new DetectionEvidence(
            probeEvId, incidentId, RuleProbe01.RULE_ID, "1.0.0",
            now.minusSeconds(60), 0.85, "MEDIUM", "observed_probing_failures >= 4",
            4, 180, 4, "{}", List.of(probeEvId), now.minusSeconds(60)
        );

        // Step 2: Adversary escalates to BOLA cross-customer exploitation (RULE-BOLA-01)
        UUID bolaEvId = UUID.randomUUID();
        DetectionEvidence bolaEvidence = new DetectionEvidence(
            bolaEvId, null, RuleBola01.RULE_ID, "1.0.0",
            now.minusSeconds(30), 0.95, "HIGH", "observed_attempts >= 3",
            3, 300, 3, "{\"distinctResources\":[\"victim-1\",\"victim-2\",\"victim-3\"]}",
            List.of(bolaEvId), now.minusSeconds(30)
        );

        RuleEvaluationResult bolaResult = RuleEvaluationResult.triggered(
            RuleBola01.RULE_ID, "1.0.0", "CUSTOMER", customerId, bolaEvidence, "BOLA probing detected"
        );

        CorrelationResult res1 = correlator.evaluateCorrelation(bolaResult, activeIncident, List.of(pastEvidence));
        assertThat(res1.correlated()).isTrue();
        assertThat(res1.isDuplicate()).isFalse();
        assertThat(res1.updatedThreatCategory()).isEqualTo("MULTI_VECTOR_CAMPAIGN");
        assertThat(res1.escalatedSeverity()).isEqualTo("HIGH");
        assertThat(res1.combinedConfidence()).isGreaterThanOrEqualTo(0.95);
        assertThat(res1.policyRule()).isEqualTo("MULTI_VECTOR_ADVISORY_POLICY");

        // Step 3: Adversary extracts high data volume (RULE-DATA-01)
        UUID dataEvId = UUID.randomUUID();
        DetectionEvidence dataEvidence = new DetectionEvidence(
            dataEvId, null, RuleData01.RULE_ID, "1.0.0",
            now, 0.92, "HIGH", "cumulative_records >= 50",
            2, 120, 2, "{}", List.of(dataEvId), now
        );

        RuleEvaluationResult dataResult = RuleEvaluationResult.triggered(
            RuleData01.RULE_ID, "1.0.0", "CUSTOMER", customerId, dataEvidence, "Excessive data access detected"
        );

        CorrelationResult res2 = correlator.evaluateCorrelation(dataResult, activeIncident, List.of(pastEvidence, bolaEvidence));
        assertThat(res2.correlated()).isTrue();
        // 3 distinct vectors (Probe -> BOLA -> Data) escalates to COMPLEX_INTRUSION and CRITICAL severity
        assertThat(res2.updatedThreatCategory()).isEqualTo("COMPLEX_INTRUSION");
        assertThat(res2.escalatedSeverity()).isEqualTo("CRITICAL");
        assertThat(res2.combinedConfidence()).isEqualTo(0.99);
    }

    @Test
    @DisplayName("Should strictly enforce Anti-Affinity: isolate distinct customers sharing corporate IP")
    void testAntiAffinitySharedIpIsolation() {
        Instant now = Instant.now();
        UUID incidentId = UUID.randomUUID();

        // Active incident is for Customer A
        SecurityIncident activeIncidentCustA = new SecurityIncident(
            incidentId, "fp-cust-a", RuleProbe01.RULE_ID, "1.0.0",
            "RECON_PROBE", "MEDIUM", IncidentStatus.OPEN,
            "CUSTOMER", "cust-A-uuid", now.minusSeconds(60), now, 4,
            "Probing for Customer A", now.minusSeconds(60), now
        );

        // New evidence is for Customer B (even if both accessed from same IP)
        UUID evId = UUID.randomUUID();
        DetectionEvidence evCustB = new DetectionEvidence(
            evId, null, RuleBola01.RULE_ID, "1.0.0", now, 0.95, "HIGH",
            "BOLA attempts >= 3", 3, 300, 3, "{}", List.of(evId), now
        );

        RuleEvaluationResult resCustB = RuleEvaluationResult.triggered(
            RuleBola01.RULE_ID, "1.0.0", "CUSTOMER", "cust-B-uuid", evCustB, "BOLA for Customer B"
        );

        CorrelationResult correlation = correlator.evaluateCorrelation(resCustB, activeIncidentCustA, List.of());

        // Anti-affinity MUST reject correlation
        assertThat(correlation.correlated()).isFalse();
    }

    @Test
    @DisplayName("Should detect idempotent redelivery of existing event IDs without inflating campaign")
    void testIdempotentRedeliveryIgnored() {
        Instant now = Instant.now();
        UUID incidentId = UUID.randomUUID();
        UUID existingEventId = UUID.randomUUID();

        SecurityIncident activeIncident = new SecurityIncident(
            incidentId, "fp-idem", RuleProbe01.RULE_ID, "1.0.0",
            "RECON_PROBE", "MEDIUM", IncidentStatus.OPEN,
            "CUSTOMER", "cust-idem", now.minusSeconds(60), now, 4,
            "Probing", now.minusSeconds(60), now
        );

        DetectionEvidence pastEvidence = new DetectionEvidence(
            UUID.randomUUID(), incidentId, RuleProbe01.RULE_ID, "1.0.0",
            now.minusSeconds(30), 0.85, "MEDIUM", "observed_probing_failures >= 4",
            4, 180, 4, "{}", List.of(existingEventId), now.minusSeconds(30)
        );

        // Re-delivered evidence with the EXACT same event ID
        DetectionEvidence redeliveredEvidence = new DetectionEvidence(
            UUID.randomUUID(), null, RuleProbe01.RULE_ID, "1.0.0",
            now, 0.85, "MEDIUM", "observed_probing_failures >= 4",
            4, 180, 4, "{}", List.of(existingEventId), now
        );

        RuleEvaluationResult redeliveredResult = RuleEvaluationResult.triggered(
            RuleProbe01.RULE_ID, "1.0.0", "CUSTOMER", "cust-idem", redeliveredEvidence, "Probing"
        );

        CorrelationResult corr = correlator.evaluateCorrelation(redeliveredResult, activeIncident, List.of(pastEvidence));

        assertThat(corr.isDuplicate()).isTrue();
    }

    @Test
    @DisplayName("Should not absorb new campaign into a closed (RESOLVED) incident")
    void testClosedIncidentDoesNotAbsorb() {
        Instant now = Instant.now();
        UUID incidentId = UUID.randomUUID();

        // Incident is RESOLVED
        SecurityIncident resolvedIncident = new SecurityIncident(
            incidentId, "fp-resolved", RuleProbe01.RULE_ID, "1.0.0",
            "RECON_PROBE", "MEDIUM", IncidentStatus.RESOLVED,
            "CUSTOMER", "cust-resolved", now.minusSeconds(1000), now.minusSeconds(500), 4,
            "Resolved incident", now.minusSeconds(1000), now.minusSeconds(500)
        );

        UUID newEventId = UUID.randomUUID();
        DetectionEvidence newEv = new DetectionEvidence(
            newEventId, null, RuleBola01.RULE_ID, "1.0.0", now, 0.95, "HIGH",
            "BOLA >= 3", 3, 300, 3, "{}", List.of(newEventId), now
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            RuleBola01.RULE_ID, "1.0.0", "CUSTOMER", "cust-resolved", newEv, "New BOLA"
        );

        CorrelationResult corr = correlator.evaluateCorrelation(result, resolvedIncident, List.of());
        assertThat(corr.correlated()).isFalse();
    }
}
