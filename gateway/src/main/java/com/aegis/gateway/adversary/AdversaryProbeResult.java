package com.aegis.gateway.adversary;

public record AdversaryProbeResult(
    String probeId,
    String method,
    String path,
    String sessionId,
    AdversaryMutationStrategy strategy,
    boolean blocked,
    int responseStatus,
    String blockReason,
    String evasionDetail
) {}
