package com.aegis.gateway.simulation.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record SimulationReport(
    String runId,
    String campaignId,
    String templateId,
    SimulationRunStatus status,
    Instant startTime,
    Instant endTime,
    long durationMs,
    SimulationRunConfig config,
    int totalStages,
    int passedStages,
    int failedStages,
    int totalRequests,
    int requests2xx,
    int requests4xx,
    int requests5xx,
    List<SimulationStageResult> stages,
    Map<String, Object> detectionAttribution,
    Map<String, Object> provenance,
    String markdownReport
) {}

