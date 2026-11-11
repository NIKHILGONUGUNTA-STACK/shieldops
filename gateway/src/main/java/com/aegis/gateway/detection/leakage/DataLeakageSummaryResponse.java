package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.detection.dto.IncidentResponse;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Summary metrics for Data Leakage and BOLA detection operations.
 */
public record DataLeakageSummaryResponse(
    long totalLeakageIncidents,
    long confirmedBolaLeaks,
    long deniedBolaAttempts,
    long sensitiveDataExposures,
    long bulkExtractionEvents,
    long multiStageCampaigns,
    Map<String, Long> incidentsBySeverity,
    Map<String, Long> incidentsByStatus,
    List<IncidentResponse> recentIncidents,
    Instant generatedAt
) {}

