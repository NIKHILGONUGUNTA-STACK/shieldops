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
    long excessiveExposures,
    long lowAndSlowExtractions,
    long distributedExtractions,
    long paginationExtractions,
    long multiResourceExtractions,
    Map<String, Long> incidentsBySeverity,
    Map<String, Long> incidentsByStatus,
    List<IncidentResponse> recentIncidents,
    Instant generatedAt
) {
    public DataLeakageSummaryResponse(
            long totalLeakageIncidents,
            long confirmedBolaLeaks,
            long deniedBolaAttempts,
            long sensitiveDataExposures,
            long bulkExtractionEvents,
            long multiStageCampaigns,
            Map<String, Long> incidentsBySeverity,
            Map<String, Long> incidentsByStatus,
            List<IncidentResponse> recentIncidents,
            Instant generatedAt) {
        this(
            totalLeakageIncidents, confirmedBolaLeaks, deniedBolaAttempts,
            sensitiveDataExposures, bulkExtractionEvents, multiStageCampaigns,
            0L, 0L, 0L, 0L, 0L,
            incidentsBySeverity, incidentsByStatus, recentIncidents, generatedAt
        );
    }
}

