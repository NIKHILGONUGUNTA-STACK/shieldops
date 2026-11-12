package com.aegis.gateway.detection.leakage;

/**
 * Metric summary for an evaluation mode (ISOLATED_RULES vs CONTEXTUAL_CORRELATION).
 */
public record ModeBenchmarkMetrics(
    String mode,
    int totalScenarios,
    int totalBenign,
    int totalMalicious,
    int truePositives,
    int falsePositives,
    int trueNegatives,
    int falseNegatives,
    double precision,
    double recall,
    double f1Score,
    double accuracy,
    double falsePositiveRate,
    double specificity,
    double medianLatencyMs,
    double p95LatencyMs,
    double processingOverheadMs
) {}
