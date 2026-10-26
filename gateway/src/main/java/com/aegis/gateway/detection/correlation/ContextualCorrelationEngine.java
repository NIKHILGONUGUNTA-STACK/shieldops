package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.model.*;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * Coordinates contextual correlation across security detection evidence records,
 * aggregating multi-event and multi-resource attacks into unified security incidents.
 */
@Service
public class ContextualCorrelationEngine {
    private static final Logger log = LoggerFactory.getLogger(ContextualCorrelationEngine.class);

    private final List<ContextualCorrelator> correlators;
    private final IncidentRepository repository;
    private final MeterRegistry meterRegistry;

    public ContextualCorrelationEngine(
            List<ContextualCorrelator> correlators,
            IncidentRepository repository,
            @Autowired(required = false) MeterRegistry meterRegistry) {
        this.correlators = correlators != null ? correlators : List.of();
        this.repository = repository;
        this.meterRegistry = meterRegistry;
        log.info("Initialized ContextualCorrelationEngine with {} correlators", this.correlators.size());
    }

    @Transactional
    public SecurityIncident correlateAndProcess(RuleEvaluationResult result) {
        if (!result.triggered() || result.evidence().isEmpty()) {
            return null;
        }

        DetectionEvidence rawEvidence = result.evidence().get();
        Instant now = Instant.now();

        // 1. Look for an active incident matching target entity (or fingerprint fallback)
        Optional<SecurityIncident> activeIncidentOpt = repository.findActiveByTarget(
            result.targetEntityType(),
            result.targetEntityValue()
        );
        if (activeIncidentOpt.isEmpty()) {
            activeIncidentOpt = repository.findActiveByFingerprint(
                computeFingerprint(result.ruleId(), result.targetEntityType(), result.targetEntityValue(), 0)
            );
        }

        if (activeIncidentOpt.isPresent()) {
            SecurityIncident activeIncident = activeIncidentOpt.get();

            // Find supporting correlator
            ContextualCorrelator correlator = findCorrelator(result.ruleId());
            List<DetectionEvidence> pastEvidences = repository.findEvidenceByIncidentId(activeIncident.id());

            CorrelationResult corrResult = correlator != null
                ? correlator.evaluateCorrelation(result, activeIncident, pastEvidences)
                : CorrelationResult.notCorrelated();

            if (corrResult.isDuplicate()) {
                log.debug("Idempotent duplicate ignored for active incident {}", activeIncident.id());
                return activeIncident;
            }

            if (corrResult.correlated()) {
                // Update active incident with correlated metrics and escalated severity
                SecurityIncident updated = new SecurityIncident(
                    activeIncident.id(),
                    activeIncident.incidentFingerprint(),
                    activeIncident.ruleId(),
                    activeIncident.ruleVersion(),
                    corrResult.updatedThreatCategory(),
                    corrResult.escalatedSeverity(),
                    activeIncident.status(),
                    activeIncident.targetEntityType(),
                    activeIncident.targetEntityValue(),
                    activeIncident.firstDetectedAt(),
                    now,
                    corrResult.totalObservedCount(),
                    String.format("Correlated BOLA campaign for %s: %d unauthorized attempts across %d distinct resources in active window",
                        activeIncident.targetEntityValue(), corrResult.totalObservedCount(), corrResult.distinctResourceCount()),
                    activeIncident.createdAt(),
                    now
                );
                repository.updateIncident(updated);

                // Persist new linked evidence with correlated confidence and distinct resource count
                DetectionEvidence linkedEvidence = new DetectionEvidence(
                    rawEvidence.id(),
                    activeIncident.id(),
                    rawEvidence.ruleId(),
                    rawEvidence.ruleVersion(),
                    rawEvidence.evaluatedAt(),
                    corrResult.combinedConfidence(),
                    corrResult.escalatedSeverity(),
                    corrResult.rationale(),
                    rawEvidence.observedCount(),
                    rawEvidence.windowSeconds(),
                    corrResult.distinctResourceCount(),
                    rawEvidence.evidenceDetails(),
                    corrResult.allContributingEventIds(),
                    now
                );
                repository.saveEvidence(linkedEvidence);

                // Record audit trail in incident status history
                IncidentStatusHistory history = new IncidentStatusHistory(
                    UUID.randomUUID(),
                    activeIncident.id(),
                    activeIncident.status().name(),
                    activeIncident.status().name(),
                    "CORRELATION_ENGINE",
                    now,
                    corrResult.rationale()
                );
                repository.saveStatusHistory(history);

                // Refresh advisory policy decision
                PolicyDecision decision = new PolicyDecision(
                    UUID.randomUUID(),
                    activeIncident.id(),
                    "CORRELATED_BOLA_CAMPAIGN_POLICY",
                    "LOG_ALERT",
                    "ADVISORY",
                    now,
                    now.plusSeconds(3600),
                    corrResult.rationale(),
                    now
                );
                repository.savePolicyDecision(decision);

                if (meterRegistry != null) {
                    meterRegistry.counter("aegis.detection.incidents.correlated").increment();
                }

                log.warn("Correlated evidence into active incident {} [{}]: {}",
                    activeIncident.id(), corrResult.escalatedSeverity(), corrResult.rationale());
                return updated;
            }
        }

        // 2. No active incident or not correlated: Create a new SecurityIncident
        UUID incidentId = UUID.randomUUID();
        String fingerprint = computeFingerprint(
            result.ruleId(),
            result.targetEntityType(),
            result.targetEntityValue(),
            now.toEpochMilli()
        );

        SecurityIncident incident = new SecurityIncident(
            incidentId,
            fingerprint,
            result.ruleId(),
            result.ruleVersion(),
            "BOLA_ATTEMPT",
            rawEvidence.severity(),
            IncidentStatus.OPEN,
            result.targetEntityType(),
            result.targetEntityValue(),
            now,
            now,
            rawEvidence.observedCount(),
            result.summary(),
            now,
            now
        );
        repository.saveIncident(incident);

        // Record initial lifecycle transition
        IncidentStatusHistory initialHistory = new IncidentStatusHistory(
            UUID.randomUUID(),
            incidentId,
            "NONE",
            IncidentStatus.OPEN.name(),
            result.ruleId(),
            now,
            "Initial detection trigger: " + rawEvidence.triggerCondition()
        );
        repository.saveStatusHistory(initialHistory);

        // Record initial advisory policy decision
        PolicyDecision decision = new PolicyDecision(
            UUID.randomUUID(),
            incidentId,
            "DEFAULT_BOLA_ADVISORY_POLICY",
            "LOG_ALERT",
            "ADVISORY",
            now,
            now.plusSeconds(3600),
            "Repeated BOLA cross-customer access probing detected. Action remains advisory per Phase 4 specification.",
            now
        );
        repository.savePolicyDecision(decision);

        // Attach incident ID to evidence and persist
        DetectionEvidence linkedEvidence = new DetectionEvidence(
            rawEvidence.id(),
            incidentId,
            rawEvidence.ruleId(),
            rawEvidence.ruleVersion(),
            rawEvidence.evaluatedAt(),
            rawEvidence.confidenceScore(),
            rawEvidence.severity(),
            rawEvidence.triggerCondition(),
            rawEvidence.observedCount(),
            rawEvidence.windowSeconds(),
            rawEvidence.distinctResources(),
            rawEvidence.evidenceDetails(),
            rawEvidence.contributingEventIds(),
            now
        );
        repository.saveEvidence(linkedEvidence);

        if (meterRegistry != null) {
            meterRegistry.counter("aegis.detection.incidents.created").increment();
        }

        log.warn("Created NEW Security Incident {} [{}]: {}", incidentId, rawEvidence.severity(), result.summary());
        return incident;
    }

    private ContextualCorrelator findCorrelator(String ruleId) {
        for (ContextualCorrelator c : correlators) {
            if (c.supports(ruleId)) {
                return c;
            }
        }
        return null;
    }

    private String computeFingerprint(String ruleId, String entityType, String entityValue, long epochMilli) {
        String raw = ruleId + ":" + entityType + ":" + entityValue + ":" + epochMilli;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            return UUID.nameUUIDFromBytes(raw.getBytes(StandardCharsets.UTF_8)).toString();
        }
    }
}
