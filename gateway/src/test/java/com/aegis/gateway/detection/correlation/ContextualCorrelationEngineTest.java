package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.model.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ContextualCorrelationEngineTest {

    private IncidentRepository repository;
    private ContextualCorrelationEngine engine;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        repository = mock(IncidentRepository.class);
        meterRegistry = new SimpleMeterRegistry();
        BolaCampaignCorrelator correlator = new BolaCampaignCorrelator();
        engine = new ContextualCorrelationEngine(List.of(correlator), repository, meterRegistry);
    }

    @Test
    @DisplayName("Should create brand new incident when no active incident exists")
    void testCreateNewIncidentWhenNoneActive() {
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
            2,
            "{\"distinctResources\":[res-1, res-2]}",
            List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-new-attacker",
            evidence,
            "First BOLA trigger"
        );

        when(repository.findActiveByTarget("CUSTOMER", "cust-new-attacker")).thenReturn(Optional.empty());

        SecurityIncident created = engine.correlateAndProcess(result);

        assertThat(created).isNotNull();
        assertThat(created.status()).isEqualTo(IncidentStatus.OPEN);
        assertThat(created.severity()).isEqualTo("HIGH");
        assertThat(created.threatCategory()).isEqualTo("BOLA_ATTEMPT");

        verify(repository).saveIncident(any(SecurityIncident.class));
        verify(repository).saveEvidence(any(DetectionEvidence.class));
        verify(repository).saveStatusHistory(any(IncidentStatusHistory.class));
        verify(repository).savePolicyDecision(any(PolicyDecision.class));
    }

    @Test
    @DisplayName("Should correlate with active incident, escalate to BOLA_CAMPAIGN, and update status history")
    void testCorrelateWithActiveIncident() {
        UUID activeIncidentId = UUID.randomUUID();
        Instant createdTime = Instant.now().minusSeconds(180);

        SecurityIncident activeIncident = new SecurityIncident(
            activeIncidentId,
            "fingerprint-123",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-attacker-1",
            createdTime,
            createdTime,
            3,
            "Initial summary",
            createdTime,
            createdTime
        );

        DetectionEvidence pastEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            activeIncidentId,
            "RULE-BOLA-01",
            "1.0.0",
            createdTime,
            0.95,
            "HIGH",
            "observed >= 3",
            3,
            300,
            2,
            "{\"distinctResources\":[r1, r2]}",
            List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()),
            createdTime
        );

        when(repository.findActiveByTarget("CUSTOMER", "cust-attacker-1"))
            .thenReturn(Optional.of(activeIncident));
        when(repository.findEvidenceByIncidentId(activeIncidentId))
            .thenReturn(List.of(pastEvidence));

        UUID newEventId = UUID.randomUUID();
        DetectionEvidence newEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "observed >= 2",
            2,
            300,
            2,
            "{\"distinctResources\":[r3, r4]}",
            List.of(newEventId),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-1",
            newEvidence,
            "Second wave attack"
        );

        SecurityIncident updated = engine.correlateAndProcess(result);

        assertThat(updated).isNotNull();
        assertThat(updated.id()).isEqualTo(activeIncidentId);
        // Multi-resource spread (r1, r2, r3, r4) escalates threat category and severity
        assertThat(updated.threatCategory()).isEqualTo("BOLA_CAMPAIGN");
        assertThat(updated.severity()).isEqualTo("CRITICAL");

        // Verify updateIncident was called, not saveIncident
        verify(repository, never()).saveIncident(any());
        verify(repository).updateIncident(any());

        // Verify correlation history was logged
        ArgumentCaptor<IncidentStatusHistory> histCaptor = ArgumentCaptor.forClass(IncidentStatusHistory.class);
        verify(repository).saveStatusHistory(histCaptor.capture());
        assertThat(histCaptor.getValue().changedBy()).isEqualTo("CORRELATION_ENGINE");

        // Metric incremented
        assertThat(meterRegistry.counter("aegis.detection.incidents.correlated").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("Should create fresh incident if previous incident was RESOLVED")
    void testOpenNewIncidentAfterResolved() {
        when(repository.findActiveByTarget("CUSTOMER", "cust-reopened-attacker"))
            .thenReturn(Optional.empty()); // No ACTIVE incident found because old one is RESOLVED

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "trigger",
            3,
            300,
            2,
            "{\"distinctResources\":[res-A, res-B]}",
            List.of(UUID.randomUUID()),
            Instant.now()
        );

        RuleEvaluationResult result = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-reopened-attacker",
            evidence,
            "Fresh attack after case resolution"
        );

        SecurityIncident created = engine.correlateAndProcess(result);

        assertThat(created).isNotNull();
        assertThat(created.status()).isEqualTo(IncidentStatus.OPEN);
        verify(repository).saveIncident(any(SecurityIncident.class));
    }

    @Test
    @DisplayName("Idempotency: Replaying duplicate evidence should not save duplicate evidence or update incident")
    void testDuplicateEvidenceReplayDoesNotSaveDuplicateEvidenceOrUpdateIncident() {
        UUID activeIncidentId = UUID.randomUUID();
        UUID existingEventId1 = UUID.randomUUID();
        UUID existingEventId2 = UUID.randomUUID();

        SecurityIncident activeIncident = new SecurityIncident(
            activeIncidentId,
            "fingerprint-123",
            "RULE-BOLA-01",
            "1.0.0",
            "BOLA_ATTEMPT",
            "HIGH",
            IncidentStatus.OPEN,
            "CUSTOMER",
            "cust-attacker-1",
            Instant.now(),
            Instant.now(),
            2,
            "Initial summary",
            Instant.now(),
            Instant.now()
        );

        DetectionEvidence pastEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            activeIncidentId,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "trigger",
            2,
            300,
            2,
            "{\"distinctResources\":[r1, r2]}",
            List.of(existingEventId1, existingEventId2),
            Instant.now()
        );

        when(repository.findActiveByTarget("CUSTOMER", "cust-attacker-1")).thenReturn(Optional.of(activeIncident));
        when(repository.findEvidenceByIncidentId(activeIncidentId)).thenReturn(List.of(pastEvidence));

        // Incoming duplicate evidence with the exact same event IDs
        DetectionEvidence duplicateEvidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            "RULE-BOLA-01",
            "1.0.0",
            Instant.now(),
            0.95,
            "HIGH",
            "duplicate trigger",
            2,
            300,
            2,
            "{\"distinctResources\":[r1, r2]}",
            List.of(existingEventId1, existingEventId2),
            Instant.now()
        );

        RuleEvaluationResult duplicateResult = RuleEvaluationResult.triggered(
            "RULE-BOLA-01",
            "1.0.0",
            "CUSTOMER",
            "cust-attacker-1",
            duplicateEvidence,
            "Duplicate delivery"
        );

        SecurityIncident returned = engine.correlateAndProcess(duplicateResult);

        assertThat(returned).isNotNull();
        assertThat(returned.id()).isEqualTo(activeIncidentId);

        // Verify repository did NOT save duplicate evidence, did NOT update incident, did NOT save status history
        verify(repository, never()).saveEvidence(any());
        verify(repository, never()).updateIncident(any());
        verify(repository, never()).saveStatusHistory(any());
    }

    @Test
    @DisplayName("Should assign correct threat categories and advisory policy rules for diverse detection rules")
    void testCreateNewIncidentForDifferentRuleTypes() {
        // Test RULE-AUTH-01
        DetectionEvidence authEv = new DetectionEvidence(
            UUID.randomUUID(), null, "RULE-AUTH-01", "1.0.0", Instant.now(),
            0.85, "MEDIUM", "observed >= 5", 5, 120, 1, "{}", List.of(UUID.randomUUID()), Instant.now()
        );
        RuleEvaluationResult authRes = RuleEvaluationResult.triggered(
            "RULE-AUTH-01", "1.0.0", "IP", "192.168.1.50", authEv, "Auth brute force"
        );
        SecurityIncident authInc = engine.correlateAndProcess(authRes);
        assertThat(authInc.threatCategory()).isEqualTo("CREDENTIAL_ACCESS");

        // Test RULE-DATA-01
        DetectionEvidence dataEv = new DetectionEvidence(
            UUID.randomUUID(), null, "RULE-DATA-01", "1.0.0", Instant.now(),
            0.85, "MEDIUM", "records >= 40", 4, 120, 4, "{}", List.of(UUID.randomUUID()), Instant.now()
        );
        RuleEvaluationResult dataRes = RuleEvaluationResult.triggered(
            "RULE-DATA-01", "1.0.0", "CUSTOMER", "cust-data", dataEv, "Excessive data access"
        );
        SecurityIncident dataInc = engine.correlateAndProcess(dataRes);
        assertThat(dataInc.threatCategory()).isEqualTo("EXCESSIVE_DATA_ACCESS");

        // Test RULE-INJ-01
        DetectionEvidence injEv = new DetectionEvidence(
            UUID.randomUUID(), null, "RULE-INJ-01", "1.0.0", Instant.now(),
            0.90, "HIGH", "SQL injection pattern", 1, 180, 1, "{}", List.of(UUID.randomUUID()), Instant.now()
        );
        RuleEvaluationResult injRes = RuleEvaluationResult.triggered(
            "RULE-INJ-01", "1.0.0", "CUSTOMER", "cust-inj", injEv, "SQL injection"
        );
        SecurityIncident injInc = engine.correlateAndProcess(injRes);
        assertThat(injInc.threatCategory()).isEqualTo("INJECTION_ATTACK");
    }

    @Test
    @DisplayName("Should correlate cross-rule sequence into MULTI_VECTOR_CAMPAIGN via MultiVectorCampaignCorrelator")
    void testCrossRuleCorrelationViaEngine() {
        ContextualCorrelationEngine multiEngine = new ContextualCorrelationEngine(
            List.of(new BolaCampaignCorrelator(), new MultiVectorCampaignCorrelator()),
            repository,
            meterRegistry
        );

        UUID activeId = UUID.randomUUID();
        Instant now = Instant.now();
        String customerId = "cust-mv-flow";

        SecurityIncident activeIncident = new SecurityIncident(
            activeId, "fp-flow", "RULE-PROBE-01", "1.0.0", "RECON_PROBE", "MEDIUM",
            IncidentStatus.OPEN, "CUSTOMER", customerId, now.minusSeconds(100), now, 4,
            "Initial probe", now.minusSeconds(100), now
        );

        DetectionEvidence pastEv = new DetectionEvidence(
            UUID.randomUUID(), activeId, "RULE-PROBE-01", "1.0.0", now.minusSeconds(50),
            0.85, "MEDIUM", "probe trigger", 4, 180, 4, "{}", List.of(UUID.randomUUID()), now.minusSeconds(50)
        );

        when(repository.findActiveByTarget("CUSTOMER", customerId)).thenReturn(Optional.of(activeIncident));
        when(repository.findEvidenceByIncidentId(activeId)).thenReturn(List.of(pastEv));

        // Incoming RULE-BOLA-01 evidence for the same customer
        DetectionEvidence bolaEv = new DetectionEvidence(
            UUID.randomUUID(), null, "RULE-BOLA-01", "1.0.0", now,
            0.95, "HIGH", "BOLA trigger", 3, 300, 3, "{}", List.of(UUID.randomUUID()), now
        );

        RuleEvaluationResult bolaRes = RuleEvaluationResult.triggered(
            "RULE-BOLA-01", "1.0.0", "CUSTOMER", customerId, bolaEv, "BOLA attack"
        );

        SecurityIncident updated = multiEngine.correlateAndProcess(bolaRes);

        assertThat(updated).isNotNull();
        assertThat(updated.threatCategory()).isEqualTo("MULTI_VECTOR_CAMPAIGN");
        assertThat(updated.severity()).isEqualTo("HIGH");
        verify(repository).updateIncident(any());
    }
}
