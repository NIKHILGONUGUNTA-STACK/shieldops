package com.aegis.gateway.detection.policy;

import java.time.Instant;

/**
 * Security policy rule definition governing advisory recommendation generation.
 */
public record SecurityPolicy(
    String id,
    String name,
    String version,
    PolicyCategory category,
    PolicyAction recommendedAction,
    String description,
    boolean enabled,
    double riskThreshold,
    String conditionExplanation,
    Instant effectiveFrom,
    Instant updatedAt
) {}
