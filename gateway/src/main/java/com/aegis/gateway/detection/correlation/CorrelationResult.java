package com.aegis.gateway.detection.correlation;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Result of evaluating contextual evidence correlation.
 */
public record CorrelationResult(
    boolean correlated,
    UUID incidentId,
    String correlationKey,
    String updatedThreatCategory,
    String escalatedSeverity,
    double combinedConfidence,
    int totalObservedCount,
    int distinctResourceCount,
    Set<String> distinctResources,
    List<UUID> allContributingEventIds,
    String rationale,
    boolean isDuplicate,
    String summary,
    String policyRule
) {
    public CorrelationResult(
            boolean correlated,
            UUID incidentId,
            String correlationKey,
            String updatedThreatCategory,
            String escalatedSeverity,
            double combinedConfidence,
            int totalObservedCount,
            int distinctResourceCount,
            Set<String> distinctResources,
            List<UUID> allContributingEventIds,
            String rationale,
            boolean isDuplicate) {
        this(
            correlated, incidentId, correlationKey, updatedThreatCategory, escalatedSeverity,
            combinedConfidence, totalObservedCount, distinctResourceCount, distinctResources,
            allContributingEventIds, rationale, isDuplicate, null, null
        );
    }

    public static CorrelationResult notCorrelated() {
        return new CorrelationResult(
            false,
            null,
            null,
            null,
            null,
            0.0,
            0,
            0,
            Set.of(),
            List.of(),
            "No correlation criteria met",
            false,
            null,
            null
        );
    }
}
