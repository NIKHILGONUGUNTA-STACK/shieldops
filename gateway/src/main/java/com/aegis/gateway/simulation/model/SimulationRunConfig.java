package com.aegis.gateway.simulation.model;

import java.util.List;

public record SimulationRunConfig(
    String templateId,
    List<String> scenarioIds,
    Integer durationSeconds,
    Double requestRate,
    Integer concurrency,
    String trafficMix,
    Long deterministicSeed,
    List<String> tenantIds,
    List<String> targetEndpoints,
    Boolean dryRun
) {}

