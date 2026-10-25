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
    String anomalyFlags,
    String resourceType,
    String resourceId,
    String errorCode,
    long responseSizeBytes,
    int recordCount
) {
    public ApiEvent(
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
            String anomalyFlags) {
        this(
            id, correlationId, timestamp, sourceIp, httpMethod, requestPath, routeId,
            statusCode, latencyMs, authSubject, authRoles, customerId, userAgent,
            payloadHash, anomalyFlags, null, null, null, 0L, 0
        );
    }
}
