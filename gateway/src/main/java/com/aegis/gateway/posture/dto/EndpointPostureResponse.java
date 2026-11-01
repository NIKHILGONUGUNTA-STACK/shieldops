package com.aegis.gateway.posture.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Complete security posture assessment dossier for an API endpoint.
 * Invariant: confirmedVulnerability is guaranteed false.
 */
public record EndpointPostureResponse(
    String endpointId,
    String httpMethod,
    String normalizedRoute,
    String serviceBoundary,
    Instant assessmentTimestamp,
    String assessmentRuleVersion,
    OverallPosture overallPosture,
    double evidenceCoveragePercentage,
    Map<String, DimensionAssessment> dimensions,
    int totalFindingsCount,
    boolean confirmedVulnerability,
    String overallExplanation,
    List<String> recommendedSteps,
    Instant lastObservedAt,
    Instant firstObservedAt,
    long totalRequests
) {}

