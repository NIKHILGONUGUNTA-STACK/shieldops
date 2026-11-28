package com.aegis.gateway.soar;

import java.time.Instant;

/**
 * Represents an active dynamic WAF ban rule applied to an IP or CIDR block.
 */
public record WafBanRule(
        String id,
        String ipOrCidr,
        String reason,
        String incidentId,
        Instant bannedAt,
        Instant expiresAt,
        String source,
        boolean active
) {
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }
}
