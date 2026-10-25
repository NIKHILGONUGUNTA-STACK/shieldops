package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

public record SecurityIncident(
    UUID id,
    String incidentFingerprint,
    String ruleId,
    String ruleVersion,
    String threatCategory,
    String severity,
    IncidentStatus status,
    String targetEntityType,
    String targetEntityValue,
    Instant firstDetectedAt,
    Instant lastEventAt,
    int eventCount,
    String summary,
    Instant createdAt,
    Instant updatedAt
) {
    public SecurityIncident withUpdatedEvents(Instant lastEvent, int additionalEvents, String newSeverity) {
        return new SecurityIncident(
            this.id,
            this.incidentFingerprint,
            this.ruleId,
            this.ruleVersion,
            this.threatCategory,
            newSeverity != null ? newSeverity : this.severity,
            this.status,
            this.targetEntityType,
            this.targetEntityValue,
            this.firstDetectedAt,
            lastEvent,
            this.eventCount + additionalEvents,
            this.summary,
            this.createdAt,
            Instant.now()
        );
    }
}
