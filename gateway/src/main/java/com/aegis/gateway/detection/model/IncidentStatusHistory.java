package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

public record IncidentStatusHistory(
    UUID id,
    UUID incidentId,
    String previousStatus,
    String newStatus,
    String changedBy,
    Instant changedAt,
    String reason
) {}
