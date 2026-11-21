package com.aegis.gateway.evaluation.model;

public record EvaluationResult(
    String id,
    String experimentId,
    String evaluationMode,
    String evaluationUnit,
    int totalSamples,
    int truePositives,
    int falsePositives,
    int trueNegatives,
    int falseNegatives,
    int uncertainHandled,
    double precision,
    double recall,
    double f1Score,
    double accuracy,
    double falsePositiveRate,
    double falseNegativeRate,
    double specificity,
    double medianLatencyMs,
    double p95LatencyMs,
    double p99LatencyMs,
    Double ciF1Lower,
    Double ciF1Upper,
    double throughputEps
) {}
