package com.aegis.gateway.evaluation.model;

public record EvaluationRobustnessFinding(
    String id,
    String experimentId,
    String testCase,
    String category,
    String expectedBehavior,
    String observedBehavior,
    boolean passed,
    String dimension
) {}
