package com.aegis.gateway.simulation.model;

import java.util.List;

public record SimulationCampaignTemplate(
    String id,
    String name,
    String description,
    List<SimulationCampaignStage> stages,
    String trafficMix,
    double defaultRequestRate,
    int defaultConcurrency,
    int defaultDurationSeconds,
    List<String> tags
) {}

