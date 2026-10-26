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
 * aggregating multi-event, multi-resource, and cross-rule attacks into unified security incidents.
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
            List<DetectionEvidence> pastEvidences = repository.findEvidenceByIncidentId(activeIncident.id());

            // Find supporting correlator (handles multi-vector or rule-specific correlation)
            ContextualCorrelator correlator = findCorrelator(result, activeIncident, pastEvidences);

            CorrelationResult corrResult = correlator != null
                ? correlator.evaluateCorrelation(result, activeIncident, pastEvidences)
                : CorrelationResult.notCorrelated();

            if (corrResult.isDuplicate()) {
                log.debug("Idempotent duplicate ignored for active incident {}", activeIncident.id());
                return activeIncident;
            }

            if (corrResult.correlated()) {
                String summary = corrResult.summary() != null ? corrResult.summary() :
                    String.format("Correlated campaign for %s %s: %d cumulative events across %d distinct resources in active window",
                        activeIncident.targetEntityType(), activeIncident.targetEntityValue(),
                        corrResult.totalObservedCount(), corrResult.distinctResourceCount());

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
                    summary,
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
                String policyRule = corrResult.policyRule() != null ? corrResult.policyRule() :
                    (activeIncident.ruleId().contains("BOLA") ? "CORRELATED_BOLA_CAMPAIGN_POLICY" : "CORRELATED_CAMPAIGN_POLICY");

                PolicyDecision decision = new PolicyDecision(
                    UUID.randomUUID(),
                    activeIncident.id(),
                    policyRule,
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

        String initialCategory = determineInitialThreatCategory(result.ruleId());
        String initialPolicyRule = "DEFAULT_" + result.ruleId().replace("-", "_") + "_ADVISORY_POLICY";
        String policyRationale = String.format(
            "%s threat detected for %s %s. Action remains advisory per Phase 4 specification.",
            result.ruleId(), result.targetEntityType(), result.targetEntityValue()
        );

        SecurityIncident incident = new SecurityIncident(
            incidentId,
            fingerprint,
            result.ruleId(),
            result.ruleVersion(),
            initialCategory,
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
            initialPolicyRule,
            "LOG_ALERT",
            "ADVISORY",
            now,
            now.plusSeconds(3600),
            policyRationale,
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

    private ContextualCorrelator findCorrelator(
            RuleEvaluationResult result,
            SecurityIncident activeIncident,
            List<DetectionEvidence> pastEvidences) {
        boolean isMultiVector = activeIncident != null && (
            !activeIncident.ruleId().equalsIgnoreCase(result.ruleId()) ||
            (pastEvidences != null && pastEvidences.stream().anyMatch(e -> !e.ruleId().equalsIgnoreCase(result.ruleId())))
        );

        if (isMultiVector) {
            for (ContextualCorrelator c : correlators) {
                if (c instanceof MultiVectorCampaignCorrelator) {
                    return c;
                }
            }
        }

        // Try specific rule correlator first (e.g. BolaCampaignCorrelator)
        for (ContextualCorrelator c : correlators) {
            if (!(c instanceof MultiVectorCampaignCorrelator) && c.supports(result.ruleId())) {
                return c;
            }
        }

        // Fallback to MultiVectorCampaignCorrelator for general rules
        for (ContextualCorrelator c : correlators) {
            if (c.supports(result.ruleId())) {
                return c;
            }
        }

        return null;
    }

    private String determineInitialThreatCategory(String ruleId) {
        if (ruleId == null) return "SECURITY_ALERT";
        return switch (ruleId.toUpperCase().trim()) {
            case "RULE-BOLA-01" -> "BOLA_ATTEMPT";
            case "RULE-AUTH-01" -> "CREDENTIAL_ACCESS";
            case "RULE-DATA-01" -> "EXCESSIVE_DATA_ACCESS";
            case "RULE-RATE-01" -> "RATE_ANOMALY";
            case "RULE-PROBE-01" -> "RECON_PROBE";
            case "RULE-INJ-01" -> "INJECTION_ATTACK";
            default -> "API_SECURITY_VIOLATION";
        };
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
