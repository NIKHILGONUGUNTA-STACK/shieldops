package com.aegis.gateway.detection.leakage;

import java.util.List;

/**
 * Aggregated response for Phase 7.2.4.3 research evaluation and adversarial robustness.
 */
public record ComparativeBenchmarkResponse(
    int datasetSize,
    ModeBenchmarkMetrics isolatedRules,
    ModeBenchmarkMetrics contextualCorrelation,
    List<RobustnessFindingResponse> robustnessFindings,
    String generatedAt
) {}
