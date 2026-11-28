package com.aegis.gateway.soar;

import java.time.Instant;

/**
 * Record tracking a revoked JWT token or subject cutoff revocation.
 */
public record TokenRevocationRecord(
        String jti,
        String subject,
        String reason,
        Instant revokedAt,
        Instant expiresAt
) {
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }
}
