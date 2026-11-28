package com.aegis.gateway.adversary;

import java.time.Instant;
import java.util.List;

public record AdversaryCampaign(
    String id,
    String name,
    String targetEndpoint,
    AdversaryMutationStrategy strategy,
    int totalProbes,
    int blockedProbes,
    int evadedProbes,
    double evasionRate,
    String status,
    Instant startedAt,
    Instant completedAt,
    List<AdversaryProbeResult> evasionTraces
) {}
