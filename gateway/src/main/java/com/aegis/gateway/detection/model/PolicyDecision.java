package com.aegis.gateway.detection.model;

import java.time.Instant;
import java.util.UUID;

public record PolicyDecision(
    UUID id,
    UUID incidentId,
    String policyRule,
    String recommendedAction,
    String enforcementLevel, // "ADVISORY" strictly in Phase 4
    Instant decidedAt,
    Instant expiresAt,
    String rationale,
    Instant createdAt
) {}
