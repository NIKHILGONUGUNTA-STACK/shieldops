package com.aegis.gateway.detection.correlation;

import java.time.Instant;
import java.util.UUID;

/**
 * Contextual dimensions of an API security event or evidence record for correlation.
 */
public record CorrelationContext(
    String customerId,
    String authSubject,
    String sourceIp,
    String resourceType,
    String resourceId,
    Instant timestamp,
    UUID eventId
) {
    public boolean hasCustomerIdentity() {
        return customerId != null && !customerId.isBlank() && !"anonymous".equalsIgnoreCase(customerId);
    }
}
