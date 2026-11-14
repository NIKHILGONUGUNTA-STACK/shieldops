package com.aegis.gateway.detection.policy;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable audit history record for security policy lifecycle and version updates.
 */
public record PolicyAuditHistory(
    UUID id,
    String policyId,
    String previousVersion,
    String newVersion,
    String changedBy,
    String changeType, // "CREATE", "UPDATE", "TOGGLE_ENABLED", "THRESHOLD_CHANGE"
    String changeReason,
    Instant changedAt
) {}
