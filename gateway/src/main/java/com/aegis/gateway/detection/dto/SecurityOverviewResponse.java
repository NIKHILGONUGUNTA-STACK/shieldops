package com.aegis.gateway.detection.dto;

import java.util.List;
import java.util.Map;

public record SecurityOverviewResponse(
    long totalEvents,
    long totalAnomalies,
    long openIncidents,
    Map<String, Long> incidentsBySeverity,
    Map<String, Long> incidentsByCategory,
    List<IncidentSummaryResponse> recentIncidents,
    List<RuleTriggerStatResponse> topTriggeredRules,
    List<TimeSeriesBucketResponse> timeSeriesTrend
) {}
