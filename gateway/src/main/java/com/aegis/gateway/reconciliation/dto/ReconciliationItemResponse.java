package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Detailed provenance, classification, and prioritization record for a reconciled API operation.
 */
public record ReconciliationItemResponse(
    String id,
    String httpMethod,
    String normalizedRoute,
    String pathPattern,
    ReconciliationCategory category,
    UUID specificationId,
    String specificationName,
    String specificationVersion,
    String operationId,
    String serviceBoundary,
    Instant firstObservedAt,
    Instant lastObservedAt,
    long totalRequests,
    Map<String, Long> statusDistribution,
    List<String> declaredMethodsForRoute,
    List<String> observedMethodsForRoute,
    Instant windowStart,
    Instant windowEnd,
    String explanation,
    ReconciliationPriority priority,
    int priorityScore,
    String matchingConfidence,
    long authFailureCount,
    long anomalyEventCount
) {
    /**
     * Backward-compatible 19-parameter constructor defaulting priority fields.
     */
    public ReconciliationItemResponse(
            String id,
            String httpMethod,
            String normalizedRoute,
            String pathPattern,
            ReconciliationCategory category,
            UUID specificationId,
            String specificationName,
            String specificationVersion,
            String operationId,
            String serviceBoundary,
            Instant firstObservedAt,
            Instant lastObservedAt,
            long totalRequests,
            Map<String, Long> statusDistribution,
            List<String> declaredMethodsForRoute,
            List<String> observedMethodsForRoute,
            Instant windowStart,
            Instant windowEnd,
            String explanation) {
        this(
            id,
            httpMethod,
            normalizedRoute,
            pathPattern,
            category,
            specificationId,
            specificationName,
            specificationVersion,
            operationId,
            serviceBoundary,
            firstObservedAt,
            lastObservedAt,
            totalRequests,
            statusDistribution,
            declaredMethodsForRoute,
            observedMethodsForRoute,
            windowStart,
            windowEnd,
            explanation,
            ReconciliationPriority.LOW,
            0,
            "HIGH",
            0L,
            0L
        );
    }
}
