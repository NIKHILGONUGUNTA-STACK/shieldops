package com.aegis.gateway.classification;

import java.time.Instant;
import java.util.Map;

/**
 * Top-level inventory summary of sensitive data classification across the Aegis platform.
 */
public record SensitiveDataInventorySummary(
    long totalMonitoredEndpoints,
    long totalClassifiedFields,
    long totalUnclassifiedFields,
    long totalFields,
    double overallCoveragePercentage,
    Map<DataSensitivityLevel, Long> countsBySensitivity,
    Map<String, ServiceClassificationSummary> serviceWiseCoverage,
    String policyVersion,
    Instant evaluatedAt
) {
    public SensitiveDataInventorySummary {
        if (countsBySensitivity == null) {
            countsBySensitivity = Map.of();
        }
        if (serviceWiseCoverage == null) {
            serviceWiseCoverage = Map.of();
        }
    }
}

