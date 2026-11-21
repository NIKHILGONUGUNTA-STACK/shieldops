package com.aegis.gateway.evaluation.model;

import java.time.Instant;

public record EvaluationDataset(
    String datasetId,
    String version,
    String manifestHash,
    int totalScenarios,
    int benignCount,
    int maliciousCount,
    int ambiguousCount,
    int incompleteCount,
    Instant createdAt
) {}
