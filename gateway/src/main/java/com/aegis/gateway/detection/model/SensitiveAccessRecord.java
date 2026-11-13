package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

/**
 * State record capturing sensitive resource access context for RULE-BULK-EXTRACT-01 and data leakage correlation.
 */
public record SensitiveAccessRecord(
    UUID eventId,
    String resourceType,
    String resourceId,
    String routeTemplate,
    int recordCount,
    long responseSizeBytes,
    String authSubject,
    Integer pageNumber,
    String highestSensitivity,
    Instant timestamp
) {
    public SensitiveAccessRecord(
            UUID eventId,
            String resourceId,
            String routeTemplate,
            int recordCount,
            long responseSizeBytes,
            Instant timestamp) {
        this(eventId, "UNKNOWN", resourceId, routeTemplate, recordCount, responseSizeBytes, null, null, "CONFIDENTIAL", timestamp);
    }
}

