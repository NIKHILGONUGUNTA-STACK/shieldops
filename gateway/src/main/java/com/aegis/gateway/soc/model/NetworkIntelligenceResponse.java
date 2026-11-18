package com.aegis.gateway.soc.model;

import java.util.List;

public record NetworkIntelligenceResponse(
    int windowHours,
    long totalObservedIps,
    List<ObservedIpRecord> observedIps
) {}
