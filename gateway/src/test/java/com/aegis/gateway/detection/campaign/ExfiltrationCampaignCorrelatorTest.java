package com.aegis.gateway.detection.campaign;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ExfiltrationCampaignCorrelatorTest {

    private CampaignRepository campaignRepository;
    private ExfiltrationCampaignCorrelator correlator;

    @BeforeEach
    void setUp() {
        campaignRepository = mock(CampaignRepository.class);
        correlator = new ExfiltrationCampaignCorrelator(campaignRepository);
    }

    private ApiEvent buildEvent(
            String id,
            String path,
            int statusCode,
            String customerId,
            String authSubject,
            String sourceIp,
            long sizeBytes,
            Instant timestamp) {
        return new ApiEvent(
            UUID.fromString(id),
            "CORR-" + id.substring(0, 8),
            timestamp != null ? timestamp : Instant.now(),
            sourceIp,
            "GET",
            path,
            "route-1",
            statusCode,
            15L,
            authSubject,
            "ROLE_CUSTOMER",
            customerId,
            "Mozilla/5.0",
            "hash123",
            "NONE",
            "ACCOUNT",
            "acc-101",
            null,
            sizeBytes,
            1,
            null,
            null,
            null
        );
    }

    @Test
    @DisplayName("Single standalone anomaly does NOT create a campaign")
    void testSingleAnomalyDoesNotCreateCampaign() {
        ApiEvent reconEvent = buildEvent(
            "10000000-0000-0000-0000-000000000001",
            "/actuator/env",
            404,
            "cust-attacker",
            "attacker-sub",
            "198.51.100.1",
            120L,
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-PROBE-01",
            "1.0.0",
            "IP",
            "198.51.100.1",
            mock(DetectionEvidence.class),
            "Probe detected"
        );

        Optional<ExfiltrationCampaign> camp = correlator.correlateEvent(reconEvent, result, null);

        assertThat(camp).isEmpty();
        verify(campaignRepository, never()).saveCampaign(any());
    }

    @Test
    @DisplayName("Multi-stage progression (Recon -> BOLA Probing) creates an active campaign")
    void testMultiStageReconThenProbingCreatesCampaign() {
        Instant now = Instant.now();

        // Stage 1: Reconnaissance
        ApiEvent reconEvent = buildEvent(
            "10000000-0000-0000-0000-000000000001",
            "/actuator/env",
            404,
            "cust-attacker",
            "attacker-sub",
            "198.51.100.1",
            120L,
            now.minusSeconds(30)
        );
        RuleEvaluationResult r1 = RuleEvaluationResult.triggered(
            "RULE-PROBE-01", "1.0.0", "IP", "198.51.100.1", mock(DetectionEvidence.class), "Probe"
        );
        correlator.correlateEvent(reconEvent, r1, null);

        // Stage 2: BOLA Probing
        ApiEvent probeEvent = buildEvent(
            "10000000-0000-0000-0000-000000000002",
            "/api/v1/customers/victim-01",
            403,
            "cust-attacker",
            "attacker-sub",
            "198.51.100.1",
            80L,
            now
        );
        RuleEvaluationResult r2 = RuleEvaluationResult.triggered(
            "RULE-BOLA-01", "1.0.0", "CUSTOMER", "cust-attacker", mock(DetectionEvidence.class), "BOLA Probing"
        );

        when(campaignRepository.findActiveByIdentity("cust-attacker", "DEFAULT_TENANT")).thenReturn(Optional.empty());

        Optional<ExfiltrationCampaign> campOpt = correlator.correlateEvent(probeEvent, r2, null);

        assertThat(campOpt).isPresent();
        ExfiltrationCampaign camp = campOpt.get();
        assertThat(camp.correlationIdentity()).isEqualTo("cust-attacker");
        assertThat(camp.stagesObserved()).contains(CampaignStage.RECONNAISSANCE, CampaignStage.AUTHORIZATION_PROBING);
        assertThat(camp.status()).isEqualTo(CampaignStatus.OPEN);
        assertThat(camp.riskScore()).isGreaterThanOrEqualTo(35.0);

        verify(campaignRepository, times(1)).saveCampaign(any(ExfiltrationCampaign.class));
        verify(campaignRepository, atLeastOnce()).saveTimelineEvent(any(CampaignTimelineEvent.class));
    }

    @Test
    @DisplayName("Anti-Affinity: Shared corporate NAT IP with distinct customer IDs maintains isolated campaigns")
    void testSharedIpDistinctIdentitiesDoNotMerge() {
        Instant now = Instant.now();
        String sharedNatIp = "203.0.113.50";

        // Alex Morgan (Benign multi-reads)
        ApiEvent alexEvent1 = buildEvent(
            "20000000-0000-0000-0000-000000000001",
            "/api/v1/customers/alex-id",
            200,
            "alex.morgan",
            "sub-alex",
            sharedNatIp,
            500L,
            now.minusSeconds(10)
        );

        // Sam Taylor (Probing victim accounts)
        ApiEvent samEvent1 = buildEvent(
            "30000000-0000-0000-0000-000000000001",
            "/actuator/health",
            404,
            "sam.taylor",
            "sub-sam",
            sharedNatIp,
            120L,
            now.minusSeconds(5)
        );
        ApiEvent samEvent2 = buildEvent(
            "30000000-0000-0000-0000-000000000002",
            "/api/v1/accounts/victim-acc",
            403,
            "sam.taylor",
            "sub-sam",
            sharedNatIp,
            90L,
            now
        );

        RuleEvaluationResult rSamRecon = RuleEvaluationResult.triggered("RULE-PROBE-01", "1.0.0", "CUSTOMER", "sam.taylor", mock(DetectionEvidence.class), "Recon");
        RuleEvaluationResult rSamBola = RuleEvaluationResult.triggered("RULE-BOLA-01", "1.0.0", "CUSTOMER", "sam.taylor", mock(DetectionEvidence.class), "Bola");

        correlator.correlateEvent(samEvent1, rSamRecon, null);
        when(campaignRepository.findActiveByIdentity("sam.taylor", "DEFAULT_TENANT")).thenReturn(Optional.empty());

        Optional<ExfiltrationCampaign> samCamp = correlator.correlateEvent(samEvent2, rSamBola, null);

        // Sam has a campaign, Alex does not
        assertThat(samCamp).isPresent();
        assertThat(samCamp.get().correlationIdentity()).isEqualTo("sam.taylor");

        // Alex's event under the shared IP must not be in Sam's campaign
        assertThat(samCamp.get().relatedEventIds()).doesNotContain(alexEvent1.id());
    }

    @Test
    @DisplayName("Duplicate event redelivery is ignored idempotently")
    void testDuplicateEventDeliveryIgnored() {
        Instant now = Instant.now();
        ApiEvent event = buildEvent(
            "40000000-0000-0000-0000-000000000001",
            "/actuator/metrics",
            404,
            "attacker-x",
            "sub-x",
            "198.51.100.99",
            100L,
            now
        );
        RuleEvaluationResult r1 = RuleEvaluationResult.triggered("RULE-PROBE-01", "1.0.0", "CUSTOMER", "attacker-x", mock(DetectionEvidence.class), "Recon");

        correlator.correlateEvent(event, r1, null);
        // Resend identical event
        correlator.correlateEvent(event, r1, null);

        // Still only 1 observation in memory, no campaign creation for single event
        verify(campaignRepository, never()).saveCampaign(any());
    }

    @Test
    @DisplayName("Missing ownership and zero response size marks evidence as INCOMPLETE")
    void testMissingMetadataProducesIncompleteEvidence() {
        Instant now = Instant.now();

        // Event 1: Reconnaissance without customer ID
        ApiEvent ev1 = buildEvent(
            "50000000-0000-0000-0000-000000000001",
            "/actuator/env",
            404,
            null, // missing customerId
            null, // missing authSubject
            "198.51.100.77",
            0L,   // zero size
            now.minusSeconds(10)
        );
        RuleEvaluationResult r1 = RuleEvaluationResult.triggered("RULE-PROBE-01", "1.0.0", "IP", "198.51.100.77", mock(DetectionEvidence.class), "Probe");
        correlator.correlateEvent(ev1, r1, null);

        // Event 2: BOLA 403 without customer ID
        ApiEvent ev2 = buildEvent(
            "50000000-0000-0000-0000-000000000002",
            "/api/v1/customers/target-cust",
            403,
            null,
            null,
            "198.51.100.77",
            0L,
            now
        );
        RuleEvaluationResult r2 = RuleEvaluationResult.triggered("RULE-BOLA-01", "1.0.0", "IP", "198.51.100.77", mock(DetectionEvidence.class), "Bola");

        when(campaignRepository.findActiveByIdentity("ANON_198.51.100.77", "DEFAULT_TENANT")).thenReturn(Optional.empty());

        Optional<ExfiltrationCampaign> camp = correlator.correlateEvent(ev2, r2, null);

        assertThat(camp).isPresent();
        assertThat(camp.get().evidenceCompleteness()).isEqualTo(CampaignEvidenceCompleteness.INCOMPLETE);
        assertThat(camp.get().missingEvidenceDetails()).contains("Missing verified caller ownership");
    }

    @Test
    @DisplayName("Campaign status state transitions validate properly")
    void testCampaignStatusTransitions() {
        assertThat(CampaignStatus.OPEN.isValidTransition(CampaignStatus.INVESTIGATING)).isTrue();
        assertThat(CampaignStatus.OPEN.isValidTransition(CampaignStatus.ESCALATED)).isTrue();
        assertThat(CampaignStatus.OPEN.isValidTransition(CampaignStatus.RESOLVED)).isTrue();
        assertThat(CampaignStatus.OPEN.isValidTransition(CampaignStatus.FALSE_POSITIVE)).isTrue();

        assertThat(CampaignStatus.INVESTIGATING.isValidTransition(CampaignStatus.RESOLVED)).isTrue();
        assertThat(CampaignStatus.INVESTIGATING.isValidTransition(CampaignStatus.OPEN)).isFalse();

        assertThat(CampaignStatus.RESOLVED.isValidTransition(CampaignStatus.OPEN)).isTrue();
        assertThat(CampaignStatus.RESOLVED.isValidTransition(CampaignStatus.FALSE_POSITIVE)).isFalse();
    }
}
