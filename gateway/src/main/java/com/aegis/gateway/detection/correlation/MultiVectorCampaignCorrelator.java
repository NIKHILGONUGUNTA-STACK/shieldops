package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Multi-vector campaign correlator.
 * Correlates independent evidence across diverse attack vectors (e.g. route probing -> BOLA -> excessive data volume)
 * into a unified campaign with Bayesian evidence combination, strict anti-affinity tenant boundaries,
 * and auditable advisory policy decisions.
 */
@Component
@Order(10)
public class MultiVectorCampaignCorrelator implements ContextualCorrelator {
    private static final Logger log = LoggerFactory.getLogger(MultiVectorCampaignCorrelator.class);

    private static final Set<String> SUPPORTED_RULES = Set.of(
        RuleBola01.RULE_ID,
        RuleAuth01.RULE_ID,
        RuleData01.RULE_ID,
        RuleRate01.RULE_ID,
        RuleProbe01.RULE_ID,
        RuleInj01.RULE_ID
    );

    @Override
    public boolean supports(String ruleId) {
        if (ruleId == null) return false;
        return SUPPORTED_RULES.contains(ruleId.toUpperCase().trim()) || "MULTI_VECTOR".equalsIgnoreCase(ruleId);
    }

    @Override
    public CorrelationResult evaluateCorrelation(
            RuleEvaluationResult newResult,
            SecurityIncident activeIncident,
            List<DetectionEvidence> pastEvidences) {

        if (!newResult.triggered() || newResult.evidence().isEmpty()) {
            return CorrelationResult.notCorrelated();
        }

        DetectionEvidence newEvidence = newResult.evidence().get();

        // 1. Anti-Affinity Rule: Verify target entity type and value match the active incident
        if (!activeIncident.targetEntityType().equalsIgnoreCase(newResult.targetEntityType()) ||
            !activeIncident.targetEntityValue().equalsIgnoreCase(newResult.targetEntityValue())) {
            log.debug("Anti-affinity triggered: evidence target {}:{} does not match incident {}:{}",
                newResult.targetEntityType(), newResult.targetEntityValue(),
                activeIncident.targetEntityType(), activeIncident.targetEntityValue());
            return CorrelationResult.notCorrelated();
        }

        // 2. Closed Incident Check: Do not absorb into non-active status
        if (activeIncident.status() != null &&
            (activeIncident.status().name().equals("RESOLVED") || activeIncident.status().name().equals("FALSE_POSITIVE"))) {
            log.debug("Closed incident {} will not absorb new campaign", activeIncident.id());
            return CorrelationResult.notCorrelated();
        }

        // 3. Collect all past contributing event IDs for deduplication
        Set<UUID> allEventIds = new LinkedHashSet<>();
        if (pastEvidences != null) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.contributingEventIds() != null) {
                    allEventIds.addAll(ev.contributingEventIds());
                }
            }
        }

        List<UUID> newEventIds = newEvidence.contributingEventIds() != null
            ? newEvidence.contributingEventIds()
            : List.of();

        // Idempotency check: if all incoming event IDs are already known, ignore as duplicate delivery
        boolean isExactDuplicate = !newEventIds.isEmpty() && allEventIds.containsAll(newEventIds);
        if (isExactDuplicate) {
            log.debug("Idempotent redelivery detected: all event IDs already present in active incident {}", activeIncident.id());
            return new CorrelationResult(
                true,
                activeIncident.id(),
                activeIncident.incidentFingerprint(),
                activeIncident.threatCategory(),
                activeIncident.severity(),
                newEvidence.confidenceScore(),
                allEventIds.size(),
                newEvidence.distinctResources(),
                Set.of(),
                new ArrayList<>(allEventIds),
                "Idempotent redelivery of existing detection evidence",
                true,
                activeIncident.summary(),
                "MULTI_VECTOR_ADVISORY_POLICY"
            );
        }

        // Add new contributing event IDs
        allEventIds.addAll(newEventIds);

        // 4. Collect all distinct rule vectors participating in this campaign
        Set<String> observedRules = new LinkedHashSet<>();
        if (activeIncident.ruleId() != null) {
            observedRules.add(activeIncident.ruleId());
        }
        if (pastEvidences != null) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.ruleId() != null) {
                    observedRules.add(ev.ruleId());
                }
            }
        }
        observedRules.add(newResult.ruleId());

        boolean isMultiVector = observedRules.size() >= 2;
        int totalObservedEvents = Math.max(activeIncident.eventCount() + newEvidence.observedCount(), allEventIds.size());
        int distinctResources = Math.max(activeIncident.eventCount(), newEvidence.distinctResources());

        // 5. Bayesian Confidence Combination (Heuristic multi-source evidence combination)
        double prevConfidence = 0.50;
        if (pastEvidences != null && !pastEvidences.isEmpty()) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.confidenceScore() > prevConfidence) {
                    prevConfidence = ev.confidenceScore();
                }
            }
        } else {
            prevConfidence = 0.60;
        }

        double newConfidence = newEvidence.confidenceScore();
        double combinedConfidence = calculateCombinedConfidence(prevConfidence, newConfidence);

        // 6. Threat Category & Severity Escalation
        String updatedCategory;
        String escalatedSeverity;
        String policyRule;

        if (isMultiVector) {
            boolean hasExfiltration = observedRules.contains(RuleData01.RULE_ID);
            boolean hasExploitation = observedRules.contains(RuleBola01.RULE_ID) || observedRules.contains(RuleInj01.RULE_ID);
            boolean hasReconnaissance = observedRules.contains(RuleProbe01.RULE_ID) || observedRules.contains(RuleAuth01.RULE_ID);

            if (observedRules.size() >= 3 || (hasExploitation && hasExfiltration)) {
                updatedCategory = "COMPLEX_INTRUSION";
                escalatedSeverity = "CRITICAL";
            } else {
                updatedCategory = "MULTI_VECTOR_CAMPAIGN";
                escalatedSeverity = combinedConfidence >= 0.95 ? "HIGH" : "MEDIUM";
            }
            policyRule = "MULTI_VECTOR_ADVISORY_POLICY";
        } else {
            updatedCategory = activeIncident.threatCategory();
            escalatedSeverity = combinedConfidence >= 0.95 ? "HIGH" : activeIncident.severity();
            policyRule = "DEFAULT_" + newResult.ruleId().replace("-", "_") + "_POLICY";
        }

        String rationale = String.format(
            "Multi-vector correlation for %s: %d distinct attack vectors (%s) with %d cumulative events (heuristic confidence: %.2f)",
            activeIncident.targetEntityValue(), observedRules.size(), String.join(", ", observedRules),
            totalObservedEvents, combinedConfidence
        );

        String summary = isMultiVector
            ? String.format("Multi-vector campaign for %s %s: correlated %d threat vectors (%s) across %d events in active window",
                activeIncident.targetEntityType(), activeIncident.targetEntityValue(),
                observedRules.size(), String.join(", ", observedRules), totalObservedEvents)
            : String.format("Correlated %s campaign for %s: %d events in active window",
                activeIncident.ruleId(), activeIncident.targetEntityValue(), totalObservedEvents);

        return new CorrelationResult(
            true,
            activeIncident.id(),
            activeIncident.incidentFingerprint(),
            updatedCategory,
            escalatedSeverity,
            combinedConfidence,
            totalObservedEvents,
            distinctResources,
            Set.of(),
            new ArrayList<>(allEventIds),
            rationale,
            false,
            summary,
            policyRule
        );
    }

    public static double calculateCombinedConfidence(double c1, double c2) {
        double p1 = Math.min(0.99, Math.max(0.01, c1));
        double p2 = Math.min(0.99, Math.max(0.01, c2));
        double combined = 1.0 - ((1.0 - p1) * (1.0 - p2));
        return Math.min(0.99, Math.round(combined * 100.0) / 100.0);
    }
}
