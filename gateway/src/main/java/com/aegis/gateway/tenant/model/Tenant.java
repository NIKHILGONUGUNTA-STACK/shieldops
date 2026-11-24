package com.aegis.gateway.tenant.model;

import java.time.Instant;
import java.util.List;

/**
 * Enterprise SaaS Tenant representation in the Aegis ShieldOps platform.
 */
public record Tenant(
    String id,
    String name,
    TenantTier tier,
    TenantStatus status,
    int rateLimitRpm,
    int maxIncidentsRetentionDays,
    List<String> allowedIpRanges,
    String contactEmail,
    String webhookUrl,
    Instant createdAt,
    Instant updatedAt
) {
    public Tenant withStatus(TenantStatus newStatus) {
        return new Tenant(
            id, name, tier, newStatus, rateLimitRpm, maxIncidentsRetentionDays,
            allowedIpRanges, contactEmail, webhookUrl, createdAt, Instant.now()
        );
    }

    public Tenant withQuotas(int newRateLimitRpm, int newRetentionDays, List<String> newAllowedIps) {
        return new Tenant(
            id, name, tier, status, newRateLimitRpm, newRetentionDays,
            newAllowedIps != null ? List.copyOf(newAllowedIps) : List.of(),
            contactEmail, webhookUrl, createdAt, Instant.now()
        );
    }
}
