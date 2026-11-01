package com.aegis.gateway.discovery.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Security incident related to an endpoint or service within the monitoring window.
 */
public record EndpointLinkedIncident(
    UUID id,
    String ruleId,
    String threatCategory,
    String severity,
    String status,
    String summary,
    Instant firstDetectedAt
) {}
