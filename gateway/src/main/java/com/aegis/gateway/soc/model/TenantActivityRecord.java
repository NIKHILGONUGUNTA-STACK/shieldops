package com.aegis.gateway.soc.model;

import java.time.Instant;

public record TenantActivityRecord(
    String tenantId,
    Instant firstSeen,
    Instant lastSeen,
    long totalRequests,
    long requests2xx,
    long requests4xx,
    long requests5xx,
    long uniqueIdentitiesCount,
    long uniqueIpsCount,
    double errorRate
) {}
