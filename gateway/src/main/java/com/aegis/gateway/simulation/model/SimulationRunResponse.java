package com.aegis.gateway.simulation.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record SimulationRunResponse(
    String runId,
    String campaignId,
    String templateId,
    SimulationRunStatus status,
    Instant startTime,
    Instant endTime,
    SimulationRunConfig config,
    List<SimulationStageResult> stages,
    int totalRequests,
    int requests2xx,
    int requests4xx,
    int requests5xx,
    boolean allAssertionsPassed,
    Map<String, Object> provenanceMetadata
) {}

