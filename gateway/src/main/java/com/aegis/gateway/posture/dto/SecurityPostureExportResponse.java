package com.aegis.gateway.posture.dto;

import java.time.Instant;
import java.util.List;

/**
 * Full export payload for security posture assessments.
 */
public record SecurityPostureExportResponse(
    String exportId,
    Instant exportedAt,
    int totalEndpoints,
    PostureSummaryResponse summary,
    List<EndpointPostureResponse> endpoints
) {}
