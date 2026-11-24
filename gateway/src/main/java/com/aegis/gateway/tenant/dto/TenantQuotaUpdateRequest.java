package com.aegis.gateway.tenant.dto;

import jakarta.validation.constraints.Positive;
import java.util.List;

public record TenantQuotaUpdateRequest(
    @Positive
    int rateLimitRpm,

    @Positive
    int maxIncidentsRetentionDays,

    List<String> allowedIpRanges
) {}
