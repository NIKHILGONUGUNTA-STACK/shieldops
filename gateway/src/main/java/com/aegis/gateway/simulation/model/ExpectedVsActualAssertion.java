package com.aegis.gateway.simulation.model;

public record ExpectedVsActualAssertion(
    String assertionType,
    String targetIdentifier,
    Object expected,
    Object actual,
    boolean passed,
    String details
) {}

