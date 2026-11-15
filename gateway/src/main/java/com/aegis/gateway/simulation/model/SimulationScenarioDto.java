package com.aegis.gateway.simulation.model;

import java.util.List;

public record SimulationScenarioDto(
    String id,
    String name,
    String description,
    String category,
    String severity,
    boolean isImplemented,
    List<String> tags,
    List<String> targetEndpoints,
    List<String> expectedOutcomes
) {}

