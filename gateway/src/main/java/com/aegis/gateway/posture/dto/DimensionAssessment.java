package com.aegis.gateway.posture.dto;

import java.util.List;

/**
 * Result evaluation for a single security posture dimension.
 */
public record DimensionAssessment(
    AssessmentDimensionType dimension,
    DimensionStatus status,
    String summary,
    List<PostureEvidenceItem> evidence,
    String limitations,
    List<String> recommendedActions
) {}

