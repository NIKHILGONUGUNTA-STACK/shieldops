package com.aegis.gateway.evaluation.model;

import java.time.Instant;

public record EvaluationExperiment(
    String experimentId,
    String datasetId,
    String experimentName,
    String status,
    Instant startedAt,
    Instant completedAt,
    String configJson,
    Instant createdAt
) {}
