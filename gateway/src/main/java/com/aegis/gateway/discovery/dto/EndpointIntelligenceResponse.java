package com.aegis.gateway.discovery.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Unified intelligence dossier for a single API endpoint combining observed wire metrics,
 * declared OpenAPI specification context, reconciliation status, discrepancy prioritization,
 * and related security incidents.
 */
public record EndpointIntelligenceResponse(
    String id,
    String httpMethod,
    String routeTemplate,
    String serviceBoundary,
    Instant firstObservedAt,
    Instant lastObservedAt,
    long totalRequests,
    Double averageLatencyMs,
    Map<String, Long> statusDistribution,
    List<Integer> distinctStatusCodes,
    EndpointSpecMetadata specification,
    EndpointReconciliationStatus reconciliation,
    EndpointPrioritizationDetail prioritization,
    long authFailureCount,
    long anomalyEventCount,
    List<EndpointLinkedIncident> linkedIncidents
) {}
