package com.aegis.gateway.simulation.model;

import java.time.Instant;
import java.util.List;

public record SimulationStageResult(
    int stageNumber,
    String stageName,
    String scenarioId,
    String status,
    int totalRequests,
    int successfulRequests,
    int failedRequests,
    Instant startTime,
    Instant endTime,
    long durationMs,
    List<ExpectedVsActualAssertion> assertionResults,
    String errorMessage
) {}

