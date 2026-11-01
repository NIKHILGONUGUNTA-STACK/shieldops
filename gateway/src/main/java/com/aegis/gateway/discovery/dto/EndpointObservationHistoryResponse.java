package com.aegis.gateway.discovery.dto;

import java.time.Instant;
import java.util.List;

/**
 * Historical time-bucketed observation analytics for an API endpoint.
 */
public record EndpointObservationHistoryResponse(
    String endpointId,
    String httpMethod,
    String routeTemplate,
    int windowHours,
    String bucketSize,
    Instant windowStart,
    Instant windowEnd,
    long totalRequests,
    List<ObservationTimeBucket> buckets,
    int retentionLimitHours
) {}
