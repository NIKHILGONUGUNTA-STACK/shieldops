package com.aegis.gateway.evaluation.dto;

import java.util.List;
import java.util.Map;

public record ExperimentImportRequest(
    String datasetId,
    String datasetVersion,
    String manifestHash,
    int totalScenarios,
    int benignCount,
    int maliciousCount,
    int ambiguousCount,
    int incompleteCount,
    String experimentId,
    String experimentName,
    Map<String, Object> resultsJson,
    List<AblationResponse> ablations,
    List<RobustnessFindingDto> robustnessFindings
) {}
