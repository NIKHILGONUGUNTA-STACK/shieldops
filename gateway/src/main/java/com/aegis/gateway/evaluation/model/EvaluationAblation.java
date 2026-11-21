package com.aegis.gateway.evaluation.model;

public record EvaluationAblation(
    String id,
    String experimentId,
    String ablationDimension,
    double precision,
    double recall,
    double f1Score,
    double falsePositiveRate,
    double f1Delta
) {}
