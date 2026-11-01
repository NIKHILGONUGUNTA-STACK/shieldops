package com.aegis.gateway.posture.dto;

import java.time.Instant;
import java.util.Map;

/**
 * Aggregated posture assessment summary metrics across assessed endpoints.
 */
public record PostureSummaryResponse(
    int totalAssessedEndpoints,
    int adequateCount,
    int attentionRequiredCount,
    int insufficientEvidenceCount,
    int verifiedDimensionsCount,
    int findingDimensionsCount,
    int unknownDimensionsCount,
    double averageEvidenceCoveragePercentage,
    Map<String, Long> distributionByService,
    Map<String, Long> distributionByPosture,
    String assessmentRuleVersion,
    Instant assessedAt
) {}

