package com.aegis.gateway.detection.leakage;

/**
 * Robustness finding response record for adversarial and edge-case evaluations.
 */
public record RobustnessFindingResponse(
    String testCase,
    String category,
    String expectedBehavior,
    String observedBehavior,
    boolean passed,
    String details
) {}
