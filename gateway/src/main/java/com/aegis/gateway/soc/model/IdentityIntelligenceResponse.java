package com.aegis.gateway.soc.model;

import java.util.List;

public record IdentityIntelligenceResponse(
    int windowHours,
    long totalObservedIdentities,
    List<ObservedIdentityRecord> observedIdentities
) {}
