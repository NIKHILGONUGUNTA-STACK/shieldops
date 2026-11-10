package com.aegis.gateway.classification;

/**
 * Service-level sensitive data classification coverage summary.
 */
public record ServiceClassificationSummary(
    String serviceName,
    long totalEndpoints,
    long classifiedFields,
    long unclassifiedFields,
    long totalFields,
    double coveragePercentage
) {
}

