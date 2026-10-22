package com.aegis.gateway.telemetry;

import java.time.Instant;
import java.util.UUID;

public record ApiEvent(
    UUID id,
    String correlationId,
    Instant timestamp,
    String sourceIp,
    String httpMethod,
    String requestPath,
    String routeId,
    int statusCode,
    long latencyMs,
    String authSubject,
    String authRoles,
    String customerId,
    String userAgent,
    String payloadHash,
    String anomalyFlags
) {}
