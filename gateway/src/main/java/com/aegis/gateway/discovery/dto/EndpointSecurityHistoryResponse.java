package com.aegis.gateway.discovery.dto;

import java.time.Instant;
import java.util.List;

/**
 * Historical security observations and linked incident context for an API endpoint.
 */
public record EndpointSecurityHistoryResponse(
    String endpointId,
    String httpMethod,
    String routeTemplate,
    int windowHours,
    Instant windowStart,
    Instant windowEnd,
    long authFailureCount,
    long anomalyEventCount,
    List<Integer> distinctStatusCodes,
    List<EndpointSecurityEvent> securityEvents,
    List<EndpointLinkedIncident> linkedIncidents
) {}
