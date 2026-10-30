package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.List;

/**
 * Complete investigation detail response for a single API reconciliation finding.
 * Connects canonical identity, explainable priority score, telemetry evidence,
 * associated specification metadata, linked incidents, and triage guidance.
 */
public record ReconciliationInvestigationResponse(
    String id,
    String httpMethod,
    String normalizedRoute,
    String pathPattern,
    ReconciliationCategory category,
    ReconciliationPriority priority,
    int priorityScore,
    String priorityRuleVersion,
    List<PriorityContributingFactor> contributingFactors,
    String matchingConfidence,
    String confidenceRationale,
    boolean confirmedVulnerability,
    String serviceBoundary,
    InvestigationSpecMetadata specification,
    InvestigationTelemetryEvidence telemetryEvidence,
    int windowHours,
    Instant windowStart,
    Instant windowEnd,
    List<String> declaredMethodsForRoute,
    List<String> observedMethodsForRoute,
    List<InvestigationLinkedIncident> linkedIncidents,
    List<String> explicitLimitations,
    List<String> recommendedSteps
) {}
