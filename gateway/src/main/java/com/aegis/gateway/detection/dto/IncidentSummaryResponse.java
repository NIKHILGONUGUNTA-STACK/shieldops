package com.aegis.gateway.detection.dto;

import java.time.Instant;
import java.util.UUID;

public record IncidentSummaryResponse(
    UUID id,
    String threatCategory,
    String severity,
    String status,
    String targetEntityValue,
    String summary,
    Instant lastEventAt
) {}
