package com.aegis.gateway.reconciliation.dto;

/**
 * Individual factor contributing to the discrepancy prioritization score.
 * Explains the transparent rationale and point delta.
 */
public record PriorityContributingFactor(
    String factorId,
    String factorName,
    int scoreDelta,
    String rationale
) {}
