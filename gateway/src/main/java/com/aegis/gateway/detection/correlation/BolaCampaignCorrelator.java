package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.RuleBola01;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contextual correlator for Broken Object-Level Authorization (BOLA) threats.
 * Correlates multiple BOLA evidence records targeting diverse resources into unified campaigns.
 */
@Component
public class BolaCampaignCorrelator implements ContextualCorrelator {
    private static final Logger log = LoggerFactory.getLogger(BolaCampaignCorrelator.class);
    private static final Pattern RESOURCE_EXTRACT_PATTERN = Pattern.compile("\\[([^\\]]+)\\]");

    @Override
    public boolean supports(String ruleId) {
        return RuleBola01.RULE_ID.equalsIgnoreCase(ruleId);
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

        // Anti-Affinity Rule: Verify target entity type and value match the active incident
        if (!activeIncident.targetEntityType().equalsIgnoreCase(newResult.targetEntityType()) ||
            !activeIncident.targetEntityValue().equalsIgnoreCase(newResult.targetEntityValue())) {
            log.debug("Anti-affinity triggered: evidence target {}:{} does not match incident {}:{}",
                newResult.targetEntityType(), newResult.targetEntityValue(),
                activeIncident.targetEntityType(), activeIncident.targetEntityValue());
            return CorrelationResult.notCorrelated();
        }

        // 1. Collect all previous contributing event IDs
        Set<UUID> allEventIds = new LinkedHashSet<>();
        if (pastEvidences != null) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.contributingEventIds() != null) {
                    allEventIds.addAll(ev.contributingEventIds());
                }
            }
        }

        // 2. Check for idempotent redelivery / replay
        List<UUID> newEventIds = newEvidence.contributingEventIds() != null
            ? newEvidence.contributingEventIds()
            : List.of();

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
                "Idempotent redelivery of existing BOLA evidence",
                true // isDuplicate = true
            );
        }

        // Add new contributing event IDs
        allEventIds.addAll(newEventIds);

        // 3. Aggregate distinct target resources across past and new evidence
        Set<String> allResources = new HashSet<>();
        if (pastEvidences != null) {
            for (DetectionEvidence ev : pastEvidences) {
                extractResourcesFromDetails(ev.evidenceDetails(), allResources);
            }
        }
        extractResourcesFromDetails(newEvidence.evidenceDetails(), allResources);

        int totalDistinctResources = Math.max(allResources.size(), newEvidence.distinctResources());
        int totalObservedEvents = Math.max(activeIncident.eventCount() + newEvidence.observedCount(), allEventIds.size());

        // 4. Bayesian Independent Evidence Confidence Combination
        // Formula: C_combined = 1.0 - (1.0 - C_prev) * (1.0 - C_new), capped at 0.99
        double prevConfidence = 0.0;
        if (pastEvidences != null && !pastEvidences.isEmpty()) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.confidenceScore() > prevConfidence) {
                    prevConfidence = ev.confidenceScore();
                }
            }
        } else {
            prevConfidence = 0.50; // default baseline if no past evidence record available
        }

        double newConfidence = newEvidence.confidenceScore();
        double combinedConfidence = calculateBayesianConfidence(prevConfidence, newConfidence);

        // 5. Determine Escalated Severity
        // Multi-resource spread (>= 4 distinct targets) or combined confidence >= 0.98 escalates to CRITICAL
        String escalatedSeverity;
        if (totalDistinctResources >= 4 || combinedConfidence >= 0.98) {
            escalatedSeverity = "CRITICAL";
        } else if (totalDistinctResources >= 2 || combinedConfidence >= 0.90) {
            escalatedSeverity = "HIGH";
        } else {
            escalatedSeverity = "MEDIUM";
        }

        // 6. Threat Category Escalation
        String updatedCategory = (pastEvidences != null && !pastEvidences.isEmpty()) || totalDistinctResources >= 3
            ? "BOLA_CAMPAIGN"
            : "BOLA_ATTEMPT";

        String rationale = String.format(
            "Contextual BOLA correlation: %d cumulative unauthorized attempts across %d distinct resources (confidence: %.2f)",
            totalObservedEvents, totalDistinctResources, combinedConfidence
        );

        return new CorrelationResult(
            true,
            activeIncident.id(),
            activeIncident.incidentFingerprint(),
            updatedCategory,
            escalatedSeverity,
            combinedConfidence,
            totalObservedEvents,
            totalDistinctResources,
            allResources,
            new ArrayList<>(allEventIds),
            rationale,
            false // not duplicate
        );
    }

    public static double calculateBayesianConfidence(double c1, double c2) {
        // Bound inputs
        double p1 = Math.min(0.99, Math.max(0.01, c1));
        double p2 = Math.min(0.99, Math.max(0.01, c2));

        // Independent evidence update: 1 - (1 - p1) * (1 - p2)
        double combined = 1.0 - ((1.0 - p1) * (1.0 - p2));
        // Cap at 0.99 to avoid certainty inflation
        return Math.min(0.99, Math.round(combined * 100.0) / 100.0);
    }

    private void extractResourcesFromDetails(String evidenceDetails, Set<String> targetSet) {
        if (evidenceDetails == null || evidenceDetails.isBlank()) return;
        Matcher m = RESOURCE_EXTRACT_PATTERN.matcher(evidenceDetails);
        if (m.find()) {
            String items = m.group(1);
            for (String part : items.split(",")) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    targetSet.add(trimmed);
                }
            }
        }
    }
}
