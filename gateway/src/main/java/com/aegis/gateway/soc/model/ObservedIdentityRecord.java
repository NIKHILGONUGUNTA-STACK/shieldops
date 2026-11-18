package com.aegis.gateway.soc.model;

import java.time.Instant;

public record ObservedIdentityRecord(
    String subject,
    String customerId,
    String roles,
    Instant firstSeen,
    Instant lastSeen,
    long totalRequests,
    long requests2xx,
    long requests4xx,
    long requests5xx,
    long uniqueIpsCount,
    long tenantCount,
    long anomalousEventsCount,
    String riskCategory
) {}
