package com.aegis.gateway.discovery.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Relevant security or anomaly event associated with an endpoint.
 */
public record EndpointSecurityEvent(
    UUID eventId,
    Instant timestamp,
    String sourceIp,
    int statusCode,
    long latencyMs,
    String anomalyFlags,
    String authSubject
) {}
