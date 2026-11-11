package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

/**
 * State record capturing sensitive resource access context for RULE-BULK-EXTRACT-01 and data leakage correlation.
 */
public record SensitiveAccessRecord(
    UUID eventId,
    String resourceId,
    String routeTemplate,
    int recordCount,
    long responseSizeBytes,
    Instant timestamp
) {}

