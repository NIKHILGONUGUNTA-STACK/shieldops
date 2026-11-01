package com.aegis.gateway.discovery.dto;

import java.time.Instant;

/**
 * Aggregated telemetry metric values within a single time window bucket.
 */
public record ObservationTimeBucket(
    Instant bucketStart,
    Instant bucketEnd,
    long requestCount,
    long count2xx,
    long count3xx,
    long count4xx,
    long count5xx,
    Double avgLatencyMs,
    Long minLatencyMs,
    Long maxLatencyMs
) {}
