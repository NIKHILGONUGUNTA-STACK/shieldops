package com.aegis.gateway.detection.dto;

import com.aegis.gateway.detection.model.IncidentStatusHistory;

import java.time.Instant;
import java.util.UUID;

public record IncidentStatusHistoryResponse(
    UUID id,
    UUID incidentId,
    String previousStatus,
    String newStatus,
    String changedBy,
    Instant changedAt,
    String reason
) {
    public static IncidentStatusHistoryResponse from(IncidentStatusHistory h) {
        return new IncidentStatusHistoryResponse(
            h.id(),
            h.incidentId(),
            h.previousStatus(),
            h.newStatus(),
            h.changedBy(),
            h.changedAt(),
            h.reason()
        );
    }
}
