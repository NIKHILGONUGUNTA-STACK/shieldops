package com.aegis.gateway.discovery.dto;

import java.util.List;

/**
 * Server-side paginated response for discovered API endpoints with summary totals.
 */
public record DiscoveredEndpointPageResponse(
    List<DiscoveredEndpointResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious,
    long totalObservedEndpoints,
    long totalObservedRequests,
    long totalMonitoredServices
) {}
