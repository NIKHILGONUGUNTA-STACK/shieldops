package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.dto.IncidentSummaryResponse;
import com.aegis.gateway.detection.dto.RuleTriggerStatResponse;
import com.aegis.gateway.detection.dto.SecurityOverviewResponse;
import com.aegis.gateway.detection.dto.TimeSeriesBucketResponse;
import com.aegis.gateway.telemetry.ApiEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@RestController
public class SecurityOverviewController {
    private static final Logger log = LoggerFactory.getLogger(SecurityOverviewController.class);

    private final ApiEventRepository apiEventRepository;
    private final IncidentRepository incidentRepository;

    public SecurityOverviewController(ApiEventRepository apiEventRepository, IncidentRepository incidentRepository) {
        this.apiEventRepository = apiEventRepository;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping(value = {"/api/v1/security/overview", "/security/overview"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<SecurityOverviewResponse> getSecurityOverview(
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours) {

        if (windowHours < 1 || windowHours > 168) {
            throw new IllegalArgumentException("Invalid windowHours: must be between 1 and 168 (up to 7 days)");
        }

        Instant cutoff = Instant.now().minus(windowHours, ChronoUnit.HOURS);

        long totalEvents = apiEventRepository.countEventsSince(cutoff);
        long totalAnomalies = apiEventRepository.countAnomaliesSince(cutoff);
        long openIncidents = incidentRepository.countOpenIncidents();
        Map<String, Long> incidentsBySeverity = incidentRepository.countIncidentsBySeverity(cutoff);
        Map<String, Long> incidentsByCategory = incidentRepository.countIncidentsByCategory(cutoff);
        List<IncidentSummaryResponse> recentIncidents = incidentRepository.findRecentIncidents(5);
        List<RuleTriggerStatResponse> topTriggeredRules = incidentRepository.findTopTriggeredRules(cutoff, 5);
        List<TimeSeriesBucketResponse> timeSeriesTrend = apiEventRepository.findTimeSeriesTrendSince(cutoff);

        SecurityOverviewResponse response = new SecurityOverviewResponse(
            totalEvents,
            totalAnomalies,
            openIncidents,
            incidentsBySeverity,
            incidentsByCategory,
            recentIncidents,
            topTriggeredRules,
            timeSeriesTrend
        );

        return ResponseEntity.ok(response);
    }
}
