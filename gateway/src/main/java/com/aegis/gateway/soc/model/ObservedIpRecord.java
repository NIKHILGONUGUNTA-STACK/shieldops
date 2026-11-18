package com.aegis.gateway.soc.model;

import java.time.Instant;

public record ObservedIpRecord(
    String ipAddress,
    Instant firstSeen,
    Instant lastSeen,
    long totalRequests,
    long requests2xx,
    long requests4xx,
    long requests5xx,
    double errorRate,
    long uniqueEndpointsCount,
    long suspiciousActivityCount,
    long tenantCount,
    long identityCount,
    String reputationStatus,
    String reputationSource
) {}
