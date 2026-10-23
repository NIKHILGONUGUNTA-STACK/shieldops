package com.aegis.gateway.telemetry;

import java.time.Instant;
import java.util.UUID;

public record SecurityEventResponse(
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
) {
    public static SecurityEventResponse from(ApiEvent event) {
        return new SecurityEventResponse(
            event.id(),
            event.correlationId(),
            event.timestamp(),
            event.sourceIp(),
            event.httpMethod(),
            event.requestPath(),
            event.routeId(),
            event.statusCode(),
            event.latencyMs(),
            event.authSubject(),
            event.authRoles(),
            event.customerId(),
            event.userAgent(),
            event.payloadHash(),
            event.anomalyFlags()
        );
    }
}
