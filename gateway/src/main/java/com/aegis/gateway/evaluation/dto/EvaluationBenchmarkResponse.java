package com.aegis.gateway.evaluation.dto;

import com.aegis.gateway.detection.leakage.ModeBenchmarkMetrics;
import java.util.List;

public record EvaluationBenchmarkResponse(
    String datasetId,
    String datasetVersion,
    String manifestHash,
    int totalScenarios,
    int benignCount,
    int maliciousCount,
    int ambiguousCount,
    int incompleteCount,
    ModeBenchmarkMetrics isolatedScenarioMetrics,
    ModeBenchmarkMetrics contextualScenarioMetrics,
    ModeBenchmarkMetrics isolatedEventMetrics,
    ModeBenchmarkMetrics contextualEventMetrics,
    ModeBenchmarkMetrics isolatedCampaignMetrics,
    ModeBenchmarkMetrics contextualCampaignMetrics,
    List<AblationResponse> ablationResults,
    List<RobustnessFindingDto> robustnessFindings,
    String executedAt
) {}
