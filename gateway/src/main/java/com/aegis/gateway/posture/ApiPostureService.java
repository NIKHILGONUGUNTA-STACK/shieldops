package com.aegis.gateway.posture;

import com.aegis.gateway.discovery.ApiDiscoveryService;
import com.aegis.gateway.discovery.dto.DiscoveredEndpointPageResponse;
import com.aegis.gateway.discovery.dto.DiscoveredEndpointResponse;
import com.aegis.gateway.discovery.dto.EndpointIntelligenceResponse;
import com.aegis.gateway.posture.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service managing evidence-aware API Security Posture Assessments.
 * Evaluates endpoints dynamically from runtime wire telemetry, OpenAPI contracts,
 * reconciliation discrepancy prioritization, and security incidents.
 */
@Service
public class ApiPostureService {

    private static final Logger log = LoggerFactory.getLogger(ApiPostureService.class);

    private final ApiDiscoveryService discoveryService;
    private final ApiPostureAssessmentEngine assessmentEngine;

    public ApiPostureService(ApiDiscoveryService discoveryService, ApiPostureAssessmentEngine assessmentEngine) {
        this.discoveryService = discoveryService;
        this.assessmentEngine = assessmentEngine;
    }

    /**
     * Assesses posture for a single endpoint by its identifier.
     */
    public Optional<EndpointPostureResponse> getEndpointPosture(String endpointId, Integer windowHours) {
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;
        Optional<EndpointIntelligenceResponse> intelOpt = discoveryService.getEndpointIntelligence(endpointId, safeHours);
        return intelOpt.map(assessmentEngine::assess);
    }

    /**
     * Retrieves paginated, filtered security posture assessments across discovered endpoints.
     */
    public PosturePageResponse getPosturePage(
            int page,
            int size,
            String service,
            String posture,
            String dimension,
            String dimensionStatus,
            String search,
            Integer windowHours) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;

        // 1. Fetch discovered endpoints from wire discovery (cap at 1000 for perimeter inventory)
        DiscoveredEndpointPageResponse epPage = discoveryService.getDiscoveredEndpoints(
            0, 1000, null, service, search, "lastObserved", "DESC"
        );
        List<DiscoveredEndpointResponse> endpoints = epPage.content() != null ? epPage.content() : Collections.emptyList();

        // 2. Assess all endpoints
        List<EndpointPostureResponse> allAssessed = new ArrayList<>();
        for (DiscoveredEndpointResponse ep : endpoints) {
            Optional<EndpointIntelligenceResponse> intelOpt = discoveryService.getEndpointIntelligence(ep.id(), safeHours);
            intelOpt.ifPresent(intel -> allAssessed.add(assessmentEngine.assess(intel)));
        }

        // 3. Compute Summary over all assessed endpoints
        PostureSummaryResponse summary = buildSummary(allAssessed);

        // 4. Apply Posture-specific filters
        List<EndpointPostureResponse> filtered = allAssessed.stream()
            .filter(p -> {
                if (posture != null && !posture.isBlank()) {
                    if (!p.overallPosture().name().equalsIgnoreCase(posture.trim())) {
                        return false;
                    }
                }
                if (dimension != null && !dimension.isBlank()) {
                    DimensionAssessment da = p.dimensions().get(dimension.toUpperCase().trim());
                    if (da == null) {
                        return false;
                    }
                    if (dimensionStatus != null && !dimensionStatus.isBlank()) {
                        if (!da.status().name().equalsIgnoreCase(dimensionStatus.trim())) {
                            return false;
                        }
                    }
                }
                return true;
            })
            .collect(Collectors.toList());

        // 5. Paginate
        long totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);
        int offset = boundedPage * boundedSize;

        List<EndpointPostureResponse> pagedContent;
        if (offset >= totalElements) {
            pagedContent = Collections.emptyList();
        } else {
            int toIndex = Math.min(offset + boundedSize, filtered.size());
            pagedContent = filtered.subList(offset, toIndex);
        }

        return new PosturePageResponse(
            pagedContent,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            boundedPage < totalPages - 1,
            boundedPage > 0,
            summary
        );
    }

    /**
     * Computes high-level aggregated summary across all assessed endpoints in scope.
     */
    public PostureSummaryResponse getPostureSummary(String service, Integer windowHours) {
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;
        DiscoveredEndpointPageResponse epPage = discoveryService.getDiscoveredEndpoints(
            0, 1000, null, service, null, "lastObserved", "DESC"
        );
        List<DiscoveredEndpointResponse> endpoints = epPage.content() != null ? epPage.content() : Collections.emptyList();

        List<EndpointPostureResponse> allAssessed = new ArrayList<>();
        for (DiscoveredEndpointResponse ep : endpoints) {
            discoveryService.getEndpointIntelligence(ep.id(), safeHours)
                .ifPresent(intel -> allAssessed.add(assessmentEngine.assess(intel)));
        }

        return buildSummary(allAssessed);
    }

    private PostureSummaryResponse buildSummary(List<EndpointPostureResponse> assessedList) {
        int total = assessedList.size();
        int adequate = 0;
        int attention = 0;
        int insufficient = 0;
        int verifiedDims = 0;
        int findingDims = 0;
        int unknownDims = 0;
        double coverageSum = 0.0;

        Map<String, Long> byService = new TreeMap<>();
        Map<String, Long> byPosture = new TreeMap<>();

        for (EndpointPostureResponse p : assessedList) {
            switch (p.overallPosture()) {
                case ADEQUATE -> adequate++;
                case ATTENTION_REQUIRED -> attention++;
                case INSUFFICIENT_EVIDENCE -> insufficient++;
            }
            byPosture.merge(p.overallPosture().name(), 1L, Long::sum);

            String svc = p.serviceBoundary() != null ? p.serviceBoundary() : "unknown-service";
            byService.merge(svc, 1L, Long::sum);

            coverageSum += p.evidenceCoveragePercentage();

            for (DimensionAssessment da : p.dimensions().values()) {
                switch (da.status()) {
                    case VERIFIED -> verifiedDims++;
                    case FINDING -> findingDims++;
                    case UNKNOWN -> unknownDims++;
                }
            }
        }

        double avgCoverage = total > 0 ? Math.round((coverageSum / total) * 10.0) / 10.0 : 0.0;

        return new PostureSummaryResponse(
            total,
            adequate,
            attention,
            insufficient,
            verifiedDims,
            findingDims,
            unknownDims,
            avgCoverage,
            byService,
            byPosture,
            ApiPostureAssessmentEngine.ASSESSMENT_RULE_VERSION,
            Instant.now()
        );
    }
}

