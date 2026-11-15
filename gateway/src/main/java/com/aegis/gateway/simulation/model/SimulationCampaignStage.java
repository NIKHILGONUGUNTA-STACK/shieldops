package com.aegis.gateway.simulation.model;

import java.util.List;

public record SimulationCampaignStage(
    int stageNumber,
    String name,
    String scenarioId,
    int iterations,
    long delayBetweenRequestsMs,
    List<String> expectedDetectionRules,
    int expectedIncidents,
    int expectedCampaigns,
    List<String> expectedPolicyActions,
    int timeoutSeconds
) {}

