package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record DetectionEvidence(
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
) {}
