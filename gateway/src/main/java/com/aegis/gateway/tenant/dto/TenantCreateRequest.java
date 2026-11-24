package com.aegis.gateway.tenant.dto;

import com.aegis.gateway.tenant.model.TenantTier;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

import java.util.List;

public record TenantCreateRequest(
    @NotBlank
    @Pattern(regexp = "^[a-z0-9-]{3,64}$", message = "Tenant ID must consist of 3-64 lowercase alphanumeric characters and hyphens")
    String id,

    @NotBlank
    String name,

    TenantTier tier,

    @Positive
    int rateLimitRpm,

    @Positive
    int maxIncidentsRetentionDays,

    List<String> allowedIpRanges,

    @Email
    String contactEmail,

    String webhookUrl
) {}
