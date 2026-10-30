package com.aegis.gateway.reconciliation.dto;

import java.util.List;

/**
 * Composite result of the prioritization scoring engine for a reconciliation item.
 */
public record ReconciliationPrioritizationResult(
    ReconciliationPriority priority,
    int score,
    String ruleVersion,
    List<PriorityContributingFactor> contributingFactors,
    String matchingConfidence,
    String confidenceRationale
) {}
