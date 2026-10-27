package com.aegis.gateway.detection.dto;

import com.aegis.gateway.detection.model.DetectionEvidence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record EvidenceResponse(
    UUID id,
    UUID incidentId,
    String ruleId,
    String ruleVersion,
    Instant evaluatedAt,
    double confidenceScore,
    String severity,
    String triggerCondition,
    int observedCount,
    int windowSeconds,
    int distinctResources,
    String evidenceDetails,
    List<UUID> contributingEventIds,
    Instant createdAt
) {
    public static EvidenceResponse from(DetectionEvidence ev) {
        return new EvidenceResponse(
            ev.id(),
            ev.incidentId(),
            ev.ruleId(),
            ev.ruleVersion(),
            ev.evaluatedAt(),
            ev.confidenceScore(),
            ev.severity(),
            ev.triggerCondition(),
            ev.observedCount(),
            ev.windowSeconds(),
            ev.distinctResources(),
            ev.evidenceDetails(),
            ev.contributingEventIds() != null ? ev.contributingEventIds() : List.of(),
            ev.createdAt()
        );
    }
}
