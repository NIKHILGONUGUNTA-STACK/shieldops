package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Detailed provenance and classification record for a reconciled API operation.
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
    String explanation
) {}

