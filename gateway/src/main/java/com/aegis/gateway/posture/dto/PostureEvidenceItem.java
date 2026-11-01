package com.aegis.gateway.posture.dto;

import java.time.Instant;

/**
 * Individual empirical evidence item supporting an assessment dimension.
 */
public record PostureEvidenceItem(
    EvidenceSourceType sourceType,
    String description,
    String metricValue,
    Instant observedAt
) {}

