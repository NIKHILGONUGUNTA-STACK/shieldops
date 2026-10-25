package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class IncidentServiceTest {

    private IncidentRepository repository;
    private IncidentService incidentService;

    @BeforeEach
    void setUp() {
        repository = mock(IncidentRepository.class);
        incidentService = new IncidentService(repository);
    }

    @Test
    @DisplayName("Should create new incident, initial status history, and advisory policy decision on first trigger")
    void testCreateNewIncidentOnFirstTrigger() {
        DetectionEvidence evidence = new DetectionEvidence(
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
            3,
            "{\"detail\":\"test\"}",
            List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-01",
            evidence,
            "BOLA probing detected"
        );

        when(repository.findActiveByFingerprint(anyString())).thenReturn(Optional.empty());

        SecurityIncident created = incidentService.processRuleResult(result);

        assertThat(created).isNotNull();
        assertThat(created.status()).isEqualTo(IncidentStatus.OPEN);
        assertThat(created.severity()).isEqualTo("HIGH");
        assertThat(created.ruleId()).isEqualTo("RULE-BOLA-01");
        assertThat(created.targetEntityType()).isEqualTo("CUSTOMER");
        assertThat(created.targetEntityValue()).isEqualTo("cust-attacker-01");
        assertThat(created.eventCount()).isEqualTo(3);

        // Verify incident was saved
        verify(repository).saveIncident(any(SecurityIncident.class));

        // Verify initial lifecycle history was saved
        ArgumentCaptor<IncidentStatusHistory> historyCaptor = ArgumentCaptor.forClass(IncidentStatusHistory.class);
        verify(repository).saveStatusHistory(historyCaptor.capture());
        IncidentStatusHistory history = historyCaptor.getValue();
        assertThat(history.previousStatus()).isEqualTo("NONE");
        assertThat(history.newStatus()).isEqualTo("OPEN");
        assertThat(history.incidentId()).isEqualTo(created.id());

        // Verify advisory policy decision was recorded
        ArgumentCaptor<PolicyDecision> policyCaptor = ArgumentCaptor.forClass(PolicyDecision.class);
        verify(repository).savePolicyDecision(policyCaptor.capture());
        PolicyDecision policy = policyCaptor.getValue();
        assertThat(policy.enforcementLevel()).isEqualTo("ADVISORY");
        assertThat(policy.recommendedAction()).isEqualTo("LOG_ALERT");
        assertThat(policy.incidentId()).isEqualTo(created.id());

        // Verify evidence was saved and linked to incident
        ArgumentCaptor<DetectionEvidence> evidenceCaptor = ArgumentCaptor.forClass(DetectionEvidence.class);
        verify(repository).saveEvidence(evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().incidentId()).isEqualTo(created.id());
    }

    @Test
    @DisplayName("Should update existing incident on repeated evidence within deduplication window")
    void testDeduplicateAndAppendEvidence() {
        UUID existingIncidentId = UUID.randomUUID();
        Instant firstSeen = Instant.now().minusSeconds(60);

        SecurityIncident existingIncident = new SecurityIncident(
            existingIncidentId,
            "fingerprint-123",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-attacker-01",
            firstSeen,
            firstSeen,
            3,
            "Initial summary",
            firstSeen,
            firstSeen
        );

        when(repository.findActiveByFingerprint(anyString())).thenReturn(Optional.of(existingIncident));

        DetectionEvidence newEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "observed >= 4",
            4,
            300,
            4,
            "{\"detail\":\"additional\"}",
            List.of(UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-01",
            newEvidence,
            "Continued BOLA probing"
        );

        SecurityIncident updated = incidentService.processRuleResult(result);

        assertThat(updated).isNotNull();
        assertThat(updated.id()).isEqualTo(existingIncidentId);
        // Event count increased: 3 + 4 = 7
        assertThat(updated.eventCount()).isEqualTo(7);

        // Verify updated, not saved anew
        verify(repository, never()).saveIncident(any(SecurityIncident.class));
        verify(repository).updateIncident(any(SecurityIncident.class));

        // Evidence linked and saved
        verify(repository).saveEvidence(argThat(ev -> ev.incidentId().equals(existingIncidentId)));
    }

    @Test
    @DisplayName("Should successfully transition incident through full lifecycle")
    void testIncidentLifecycleTransitions() {
        UUID incidentId = UUID.randomUUID();
        SecurityIncident incident = new SecurityIncident(
            incidentId,
            "fp-lifecycle",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-user-01",
            Instant.now(),
            Instant.now(),
            3,
            "Probing",
            Instant.now(),
            Instant.now()
        );

        when(repository.findAllIncidents()).thenReturn(List.of(incident));

        // Transition 1: OPEN -> INVESTIGATING
        SecurityIncident s1 = incidentService.transitionStatus(incidentId, IncidentStatus.INVESTIGATING, "analyst-1", "Reviewing logs");
        assertThat(s1.status()).isEqualTo(IncidentStatus.INVESTIGATING);
        verify(repository).saveStatusHistory(argThat(h ->
            h.previousStatus().equals("OPEN") &&
            h.newStatus().equals("INVESTIGATING") &&
            h.changedBy().equals("analyst-1")
        ));

        // Transition 2: INVESTIGATING -> RESOLVED
        when(repository.findAllIncidents()).thenReturn(List.of(s1));
        SecurityIncident s2 = incidentService.transitionStatus(incidentId, IncidentStatus.RESOLVED, "analyst-1", "Advisory alert confirmed, user notified");
        assertThat(s2.status()).isEqualTo(IncidentStatus.RESOLVED);
        verify(repository).saveStatusHistory(argThat(h ->
            h.previousStatus().equals("INVESTIGATING") &&
            h.newStatus().equals("RESOLVED")
        ));
    }

    @Test
    @DisplayName("Should do nothing when evaluation result is not triggered")
    void testNotTriggeredResult() {
        RuleEvaluationResult result = RuleEvaluationResult.notTriggered("RULE-BOLA-01", "1.0.0");
        SecurityIncident incident = incidentService.processRuleResult(result);

        assertThat(incident).isNull();
        verifyNoInteractions(repository);
    }
}
