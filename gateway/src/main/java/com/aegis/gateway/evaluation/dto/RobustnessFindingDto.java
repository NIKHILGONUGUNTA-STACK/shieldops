package com.aegis.gateway.evaluation.dto;

public record RobustnessFindingDto(
    String testCase,
    String category,
    String expectedBehavior,
    String observedBehavior,
    boolean passed,
    String dimension
) {}
