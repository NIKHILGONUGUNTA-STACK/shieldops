package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;
import com.aegis.gateway.detection.campaign.CampaignStage;
import com.aegis.gateway.detection.campaign.ExfiltrationCampaign;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AdaptivePolicyEngineTest {

    private PolicyRepository policyRepository;
    private AdaptivePolicyEngine engine;

    @BeforeEach
    void setUp() {
        policyRepository = mock(PolicyRepository.class);
        engine = new AdaptivePolicyEngine(policyRepository);

        // Mock policy registry lookup
        when(policyRepository.findPolicyById("POL-BOLA-CONFIRMED-01")).thenReturn(Optional.of(
            new SecurityPolicy("POL-BOLA-CONFIRMED-01", "Confirmed BOLA", "1.0.0",
                PolicyCategory.AUTHORIZATION, PolicyAction.ESCALATE_INCIDENT, "desc", true, 85.0, "cond", Instant.now(), Instant.now())
        ));
        when(policyRepository.findPolicyById("POL-CAMPAIGN-01")).thenReturn(Optional.of(
            new SecurityPolicy("POL-CAMPAIGN-01", "Campaign Escalation", "1.0.0",
                PolicyCategory.CAMPAIGN, PolicyAction.PRIORITIZE_CAMPAIGN, "desc", true, 85.0, "cond", Instant.now(), Instant.now())
        ));
        when(policyRepository.findPolicyById("POL-AMBIGUOUS-EVIDENCE-01")).thenReturn(Optional.of(
            new SecurityPolicy("POL-AMBIGUOUS-EVIDENCE-01", "Ambiguous Evidence", "1.0.0",
                PolicyCategory.EVIDENCE_INTEGRITY, PolicyAction.REQUEST_ADDITIONAL_EVIDENCE, "desc", true, 30.0, "cond", Instant.now(), Instant.now())
        ));
        when(policyRepository.findPolicyById("POL-RECON-01")).thenReturn(Optional.of(
            new SecurityPolicy("POL-RECON-01", "Recon Monitor", "1.0.0",
                PolicyCategory.RECONNAISSANCE, PolicyAction.MONITOR_ACTIVITY, "desc", true, 20.0, "cond", Instant.now(), Instant.now())
        ));
    }

    @Test
    @DisplayName("Confirmed BOLA incident recommends ESCALATE_INCIDENT with CRITICAL severity")
    void evaluateIncidentConfirmedBola() {
        UUID incId = UUID.randomUUID();
        SecurityIncident incident = new SecurityIncident(
            incId, "FP-001", "RULE-BOLA-CONFIRMED-01", "1.0.0", "BOLA",
            "CRITICAL", IncidentStatus.OPEN, "CUSTOMER_ID", "cust-victim-1",
            Instant.now(), Instant.now(), 1, "Confirmed BOLA cross-owner leak",
            Instant.now(), Instant.now()
        );

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(), incId, "RULE-BOLA-CONFIRMED-01", "1.0.0",
            Instant.now(), 0.95, "CRITICAL", "200 on cross-owner resource",
            1, 60, 1, "T1020", List.of(UUID.randomUUID()), Instant.now()
        );

        AdaptivePolicyDecision decision = engine.evaluateIncident(incident, List.of(evidence));

        assertThat(decision).isNotNull();
        assertThat(decision.policyId()).isEqualTo("POL-BOLA-CONFIRMED-01");
        assertThat(decision.recommendedAction()).isEqualTo(PolicyAction.ESCALATE_INCIDENT);
        assertThat(decision.riskLevel()).isEqualTo("CRITICAL");
        assertThat(decision.enforcementLevel()).isEqualTo("ADVISORY");
        assertThat(decision.evidenceCompleteness()).isEqualTo(CampaignEvidenceCompleteness.COMPLETE);
        verify(policyRepository).savePolicyDecision(any(AdaptivePolicyDecision.class));
    }

    @Test
    @DisplayName("Incomplete or degraded incident evidence suppresses severe action and requests additional evidence")
    void evaluateIncidentIncompleteEvidence() {
        UUID incId = UUID.randomUUID();
        SecurityIncident incident = new SecurityIncident(
            incId, "FP-002", "RULE-BOLA-CONFIRMED-01", "1.0.0", "BOLA",
            "CRITICAL", IncidentStatus.OPEN, "UNKNOWN", "UNKNOWN", // Incomplete target entity
            Instant.now(), Instant.now(), 1, "Ambiguous leak",
            Instant.now(), Instant.now()
        );

        AdaptivePolicyDecision decision = engine.evaluateIncident(incident, Collections.emptyList());

        assertThat(decision).isNotNull();
        assertThat(decision.policyId()).isEqualTo("POL-AMBIGUOUS-EVIDENCE-01");
        assertThat(decision.recommendedAction()).isEqualTo(PolicyAction.REQUEST_ADDITIONAL_EVIDENCE);
        assertThat(decision.riskLevel()).isEqualTo("MEDIUM");
        assertThat(decision.rationale()).contains("Severe response suppressed");
        assertThat(decision.evidenceCompleteness()).isEqualTo(CampaignEvidenceCompleteness.INCOMPLETE);
    }

    @Test
    @DisplayName("Multi-stage exfiltration campaign recommends PRIORITIZE_CAMPAIGN with CRITICAL severity")
    void evaluateCampaignMultiStage() {
        UUID campId = UUID.randomUUID();
        ExfiltrationCampaign campaign = new ExfiltrationCampaign(
            campId, "CAMP-001", "cust-attacker", "tenant-aegis", "198.51.100.10",
            CampaignStage.BULK_EXTRACTION,
            List.of(CampaignStage.RECONNAISSANCE, CampaignStage.AUTHORIZATION_PROBING, CampaignStage.BULK_EXTRACTION),
            com.aegis.gateway.detection.campaign.CampaignStatus.OPEN,
            "CRITICAL", 92.5, "CRITICAL", "Recon followed by probing and extraction",
            CampaignEvidenceCompleteness.COMPLETE, null,
            3, 4, 2, Instant.now().minusSeconds(3600), Instant.now(), 15,
            List.of(), List.of(), List.of("RULE-BOLA-01"),
            Instant.now(), Instant.now()
        );

        AdaptivePolicyDecision decision = engine.evaluateCampaign(campaign, List.of("telemetry://ev-1"), null);

        assertThat(decision).isNotNull();
        assertThat(decision.policyId()).isEqualTo("POL-CAMPAIGN-01");
        assertThat(decision.recommendedAction()).isEqualTo(PolicyAction.PRIORITIZE_CAMPAIGN);
        assertThat(decision.riskLevel()).isEqualTo("CRITICAL");
        assertThat(decision.enforcementLevel()).isEqualTo("ADVISORY");
        assertThat(decision.evidenceSnapshot()).contains("riskScore\":92.5");
        verify(policyRepository).savePolicyDecision(any(AdaptivePolicyDecision.class));
    }

    @Test
    @DisplayName("Disabled policy falls back to MONITOR_ACTIVITY and annotates rationale")
    void disabledPolicyHandling() {
        when(policyRepository.findPolicyById("POL-BOLA-CONFIRMED-01")).thenReturn(Optional.of(
            new SecurityPolicy("POL-BOLA-CONFIRMED-01", "Confirmed BOLA", "1.0.0",
                PolicyCategory.AUTHORIZATION, PolicyAction.ESCALATE_INCIDENT, "desc", false, // DISABLED
                85.0, "cond", Instant.now(), Instant.now())
        ));

        UUID incId = UUID.randomUUID();
        SecurityIncident incident = new SecurityIncident(
            incId, "FP-003", "RULE-BOLA-CONFIRMED-01", "1.0.0", "BOLA",
            "CRITICAL", IncidentStatus.OPEN, "CUSTOMER_ID", "cust-1",
            Instant.now(), Instant.now(), 1, "Confirmed BOLA",
            Instant.now(), Instant.now()
        );

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(), incId, "RULE-BOLA-CONFIRMED-01", "1.0.0",
            Instant.now(), 0.95, "CRITICAL", "200 on cross-owner",
            1, 60, 1, "T1020", List.of(UUID.randomUUID()), Instant.now()
        );

        AdaptivePolicyDecision decision = engine.evaluateIncident(incident, List.of(evidence));

        assertThat(decision).isNotNull();
        assertThat(decision.recommendedAction()).isEqualTo(PolicyAction.MONITOR_ACTIVITY);
        assertThat(decision.rationale()).contains("[POLICY POL-BOLA-CONFIRMED-01 DISABLED]");
    }

    @Test
    @DisplayName("Deterministic evaluation: identical inputs produce identical recommendations and snapshots")
    void deterministicReproducibility() {
        UUID incId = UUID.randomUUID();
        SecurityIncident incident = new SecurityIncident(
            incId, "FP-004", "RULE-PROBE-01", "1.0.0", "PROBING",
            "LOW", IncidentStatus.OPEN, "IP_ADDRESS", "198.51.100.10",
            Instant.now(), Instant.now(), 1, "Recon scan",
            Instant.now(), Instant.now()
        );

        AdaptivePolicyDecision d1 = engine.evaluateIncident(incident, List.of(
            new DetectionEvidence(UUID.randomUUID(), incId, "RULE-PROBE-01", "1.0.0", Instant.now(), 0.8, "LOW", "404", 1, 60, 1, "T1595", List.of(), Instant.now())
        ));
        AdaptivePolicyDecision d2 = engine.evaluateIncident(incident, List.of(
            new DetectionEvidence(UUID.randomUUID(), incId, "RULE-PROBE-01", "1.0.0", Instant.now(), 0.8, "LOW", "404", 1, 60, 1, "T1595", List.of(), Instant.now())
        ));

        assertThat(d1.policyId()).isEqualTo(d2.policyId());
        assertThat(d1.recommendedAction()).isEqualTo(d2.recommendedAction());
        assertThat(d1.riskLevel()).isEqualTo(d2.riskLevel());
        assertThat(d1.rationale()).isEqualTo(d2.rationale());
        assertThat(d1.evidenceSnapshot()).isEqualTo(d2.evidenceSnapshot());
    }
}
