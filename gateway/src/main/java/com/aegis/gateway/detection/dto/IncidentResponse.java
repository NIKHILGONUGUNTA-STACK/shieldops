package com.aegis.gateway.detection.dto;

import com.aegis.gateway.detection.model.SecurityIncident;

import java.time.Instant;
import java.util.UUID;

public record IncidentResponse(
    UUID id,
    String incidentFingerprint,
    String ruleId,
    String ruleVersion,
    String threatCategory,
    String severity,
    String status,
    String targetEntityType,
    String targetEntityValue,
    Instant firstDetectedAt,
    Instant lastEventAt,
    int eventCount,
    String summary,
    Instant createdAt,
    Instant updatedAt
) {
    public static IncidentResponse from(SecurityIncident inc) {
        return new IncidentResponse(
            inc.id(),
            inc.incidentFingerprint(),
            inc.ruleId(),
            inc.ruleVersion(),
            inc.threatCategory(),
            inc.severity(),
            inc.status().name(),
            inc.targetEntityType(),
            inc.targetEntityValue(),
            inc.firstDetectedAt(),
            inc.lastEventAt(),
            inc.eventCount(),
            inc.summary(),
            inc.createdAt(),
            inc.updatedAt()
        );
    }
}
