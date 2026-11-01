package com.aegis.gateway.discovery.dto;

import com.aegis.gateway.reconciliation.dto.PriorityContributingFactor;
import java.util.List;

/**
 * Deterministic discrepancy prioritization breakdown for an endpoint finding.
 */
public record EndpointPrioritizationDetail(
    String priority,
    int priorityScore,
    String ruleVersion,
    List<PriorityContributingFactor> contributingFactors,
    boolean confirmedVulnerability
) {}
