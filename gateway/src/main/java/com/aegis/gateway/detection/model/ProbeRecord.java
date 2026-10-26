package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

/**
 * State record capturing probing and validation failure context for RULE-PROBE-01.
 */
public record ProbeRecord(
    UUID eventId,
    String path,
    String payloadHash,
    int statusCode,
    Instant timestamp
) {}
