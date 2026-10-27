package com.aegis.gateway.detection.dto;

import com.aegis.gateway.detection.model.PolicyDecision;

import java.time.Instant;
import java.util.UUID;

public record PolicyDecisionResponse(
    UUID id,
    UUID incidentId,
    String policyRule,
    String recommendedAction,
    String enforcementLevel,
    Instant decidedAt,
    Instant expiresAt,
    String rationale,
    Instant createdAt
) {
    public static PolicyDecisionResponse from(PolicyDecision d) {
        return new PolicyDecisionResponse(
            d.id(),
            d.incidentId(),
            d.policyRule(),
            d.recommendedAction(),
            d.enforcementLevel(),
            d.decidedAt(),
            d.expiresAt(),
            d.rationale(),
            d.createdAt()
        );
    }
}
