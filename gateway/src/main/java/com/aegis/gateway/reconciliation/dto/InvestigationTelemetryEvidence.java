package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Persisted telemetry evidence observed on the gateway wire for a specific route finding.
 */
public record InvestigationTelemetryEvidence(
    long totalRequests,
    Instant firstObservedAt,
    Instant lastObservedAt,
    Map<String, Long> statusDistribution,
    long authFailureCount,
    long anomalyEventCount,
    List<Integer> distinctStatusCodes
) {}
