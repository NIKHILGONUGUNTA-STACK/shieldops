package com.aegis.gateway.evaluation.dto;

public record AblationResponse(
    String dimension,
    double precision,
    double recall,
    double f1Score,
    double falsePositiveRate,
    double f1Delta
) {}
