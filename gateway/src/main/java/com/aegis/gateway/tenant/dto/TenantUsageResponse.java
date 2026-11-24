package com.aegis.gateway.tenant.dto;

import java.time.Instant;

public record TenantUsageResponse(
    String tenantId,
    String tenantName,
    int rateLimitRpm,
    long currentWindowRequests,
    double rateLimitUtilizationPercent,
    long totalRecordedEvents,
    int activeIncidentsCount,
    int activeCampaignsCount,
    Instant evaluatedAt
) {}
