package com.aegis.gateway.detection.policy;

import java.time.Instant;
import java.util.UUID;

/**
 * Audit record of an analyst action (approval, rejection, review comment) on a policy decision.
 */
public record PolicyDecisionAction(
    UUID id,
    UUID decisionId,
    String action, // "APPROVED", "REJECTED", "COMMENT"
    String analystUser,
    String analystComment,
    Instant actionAt
) {}
