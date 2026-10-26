package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

/**
 * State record capturing data extraction metrics for RULE-DATA-01.
 */
public record DataVolumeRecord(
    UUID eventId,
    int recordCount,
    long responseSizeBytes,
    Instant timestamp
) {}
