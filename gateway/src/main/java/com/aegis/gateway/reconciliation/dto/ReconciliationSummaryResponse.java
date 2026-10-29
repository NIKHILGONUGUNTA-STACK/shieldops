package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Summary metrics of reconciliation coverage across a specified observation window and scope.
 */
public record ReconciliationSummaryResponse(
    long matchedCount,
    long observedUndocumentedCount,
    long documentedUnobservedCount,
    long methodMismatchCount,
    long ambiguousCount,
    long totalEvaluated,
    double coveragePercentage,
    int windowHours,
    Instant windowStart,
    Instant windowEnd,
    UUID specificationId,
    String specificationName
) {}

