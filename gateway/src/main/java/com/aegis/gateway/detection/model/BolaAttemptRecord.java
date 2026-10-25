package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

public record BolaAttemptRecord(
    UUID eventId,
    String resourceId,
    Instant timestamp
) {}
