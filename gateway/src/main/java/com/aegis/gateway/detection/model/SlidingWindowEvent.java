package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Generic sliding-window event record for time-bounded rule evaluation.
 */
public record SlidingWindowEvent(
    UUID eventId,
    String metadata,
    Instant timestamp
) {}
