package com.aegis.gateway.discovery;

import com.aegis.gateway.discovery.dto.*;
import com.aegis.gateway.reconciliation.ApiDiscrepancyPrioritizer;
import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationPrioritizationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for consolidating wire telemetry into an inventory of observed API endpoints,
 * generating endpoint intelligence dossiers, and computing observation & security histories.
 */
@Service
public class ApiDiscoveryService {

    private final ApiDiscoveryRepository discoveryRepository;
    private final ApiDiscrepancyPrioritizer prioritizer;

    @Autowired
    public ApiDiscoveryService(
            ApiDiscoveryRepository discoveryRepository,
            @Autowired(required = false) ApiDiscrepancyPrioritizer prioritizer) {
        this.discoveryRepository = discoveryRepository;
        this.prioritizer = prioritizer != null ? prioritizer : new ApiDiscrepancyPrioritizer();
    }

    public ApiDiscoveryService(ApiDiscoveryRepository discoveryRepository) {
        this(discoveryRepository, new ApiDiscrepancyPrioritizer());
    }

    /**
     * Discovers observed endpoints with filtering, sorting, and pagination.
     */
    public DiscoveredEndpointPageResponse getDiscoveredEndpoints(
            int page,
            int size,
            String httpMethod,
            String serviceName,
            String search,
            String sortBy,
            String sortDirection) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);

        List<DiscoveredEndpointResponse> allEndpoints = aggregateAndConsolidateEndpoints(httpMethod);

        // Global metrics before filtering
        long totalObservedEndpoints = allEndpoints.size();
        long totalObservedRequests = allEndpoints.stream().mapToLong(DiscoveredEndpointResponse::totalRequests).sum();
        long totalMonitoredServices = allEndpoints.stream().map(DiscoveredEndpointResponse::serviceName).distinct().count();

        // Apply filters
        List<DiscoveredEndpointResponse> filtered = allEndpoints.stream()
            .filter(ep -> {
                if (serviceName != null && !serviceName.isBlank()) {
                    if (!ep.serviceName().equalsIgnoreCase(serviceName.trim())) {
                        return false;
                    }
                }
                if (search != null && !search.isBlank()) {
                    String query = search.toLowerCase().trim();
                    boolean matchRoute = ep.routeTemplate().toLowerCase().contains(query);
                    boolean matchService = ep.serviceName().toLowerCase().contains(query);
                    boolean matchMethod = ep.httpMethod().toLowerCase().contains(query);
                    if (!matchRoute && !matchService && !matchMethod) {
                        return false;
                    }
                }
                return true;
            })
            .collect(Collectors.toList());

        // Sort results
        Comparator<DiscoveredEndpointResponse> comparator = getComparator(sortBy, sortDirection);
        filtered.sort(comparator);

        // Paginate
        long totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);
        int offset = boundedPage * boundedSize;

        List<DiscoveredEndpointResponse> pagedContent;
        if (offset >= totalElements) {
            pagedContent = Collections.emptyList();
        } else {
            int toIndex = Math.min(offset + boundedSize, (int) totalElements);
            pagedContent = filtered.subList(offset, toIndex);
        }

        boolean hasNext = boundedPage < (totalPages - 1);
        boolean hasPrevious = boundedPage > 0 && totalPages > 0;

        return new DiscoveredEndpointPageResponse(
            pagedContent,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            hasNext,
            hasPrevious,
            totalObservedEndpoints,
            totalObservedRequests,
            totalMonitoredServices
        );
    }

    public Optional<DiscoveredEndpointResponse> getEndpointById(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        return aggregateAndConsolidateEndpoints(null).stream()
            .filter(ep -> ep.id().equalsIgnoreCase(id.trim()))
            .findFirst();
    }

    /**
     * Compiles unified endpoint intelligence combining wire telemetry, OpenAPI specification context,
     * reconciliation classification, discrepancy prioritization, and correlated security incidents.
     */
    public Optional<EndpointIntelligenceResponse> getEndpointIntelligence(String endpointId, Integer windowHours) {
        Optional<DiscoveredEndpointResponse> epOpt = getEndpointById(endpointId);
        if (epOpt.isEmpty()) {
            return Optional.empty();
        }

        DiscoveredEndpointResponse ep = epOpt.get();
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;
        Instant now = Instant.now();
        Instant windowStart = now.minus(Duration.ofHours(safeHours));

        // 1. Status codes for this route in the window
        List<Integer> distinctStatuses = discoveryRepository.findDistinctStatusCodesForRoute(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now
        );
        if (distinctStatuses.isEmpty()) {
            distinctStatuses = ep.distinctStatusCodes();
        }

        // 2. Auth failures and anomaly counts
        ApiDiscoveryRepository.SecurityCounts secCounts = discoveryRepository.findSecurityCountsForEndpoint(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now
        );

        // 3. Find matching declared OpenAPI operation
        Optional<EndpointSpecMetadata> specOpt = discoveryRepository.findDeclaredOperationForEndpoint(
            ep.httpMethod(), ep.routeTemplate()
        );

        // 4. Reconciliation Status
        ReconciliationCategory reconCat;
        String explanation;
        String matchingConfidence;
        String confidenceRationale;

        if (specOpt.isPresent()) {
            reconCat = ReconciliationCategory.MATCHED;
            explanation = "Observed HTTP method and route template match declared OpenAPI contract.";
            matchingConfidence = "HIGH";
            confidenceRationale = "Direct route normalization match with active OpenAPI specification.";
        } else {
            reconCat = ReconciliationCategory.OBSERVED_UNDOCUMENTED;
            explanation = "Active telemetry observed on wire but route is absent from active OpenAPI specifications.";
            matchingConfidence = "HIGH";
            confidenceRationale = "Direct route normalization observed on wire without declared contract.";
        }

        EndpointReconciliationStatus reconStatus = new EndpointReconciliationStatus(
            reconCat.name(), explanation, matchingConfidence, confidenceRationale
        );

        // 5. Prioritization
        ReconciliationPrioritizationResult prioResult = prioritizer.prioritize(
            reconCat,
            ep.routeTemplate(),
            ep.serviceName(),
            ep.totalRequests(),
            secCounts.authFailures(),
            secCounts.anomalyEvents(),
            ep.firstObservedAt(),
            ep.lastObservedAt(),
            false
        );

        EndpointPrioritizationDetail prioDetail = new EndpointPrioritizationDetail(
            prioResult.priority().name(),
            prioResult.score(),
            prioResult.ruleVersion(),
            prioResult.contributingFactors(),
            false // Defensive invariant: confirmedVulnerability is ALWAYS false
        );

        // 6. Linked security incidents
        List<EndpointLinkedIncident> linkedIncidents = discoveryRepository.findLinkedIncidentsForEndpoint(
            ep.serviceName(), ep.routeTemplate(), windowStart, now
        );

        return Optional.of(new EndpointIntelligenceResponse(
            ep.id(),
            ep.httpMethod(),
            ep.routeTemplate(),
            ep.serviceName(),
            ep.firstObservedAt(),
            ep.lastObservedAt(),
            ep.totalRequests(),
            ep.averageLatencyMs(),
            ep.statusDistribution(),
            distinctStatuses,
            specOpt.orElse(null),
            reconStatus,
            prioDetail,
            secCounts.authFailures(),
            secCounts.anomalyEvents(),
            linkedIncidents
        ));
    }

    /**
     * Generates server-side time-bucketed observation analytics for an endpoint with zero-filled missing intervals.
     */
    public Optional<EndpointObservationHistoryResponse> getEndpointObservationHistory(
            String endpointId,
            Integer windowHours,
            String bucket) {

        Optional<DiscoveredEndpointResponse> epOpt = getEndpointById(endpointId);
        if (epOpt.isEmpty()) {
            return Optional.empty();
        }

        DiscoveredEndpointResponse ep = epOpt.get();
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;
        String safeBucket = (bucket != null && bucket.equalsIgnoreCase("1d")) ? "1d" : "1h";
        if (safeHours > 168 && (bucket == null || bucket.isBlank())) {
            safeBucket = "1d";
        }

        Instant now = Instant.now();
        Instant windowStart = now.minus(Duration.ofHours(safeHours));

        String truncInterval = safeBucket.equals("1d") ? "day" : "hour";
        List<ApiDiscoveryRepository.RawObservationBucket> rawBuckets = discoveryRepository.findRawObservationBuckets(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now, truncInterval
        );

        // Map raw buckets by truncated timestamp for O(1) lookup
        Map<Instant, ApiDiscoveryRepository.RawObservationBucket> rawMap = new HashMap<>();
        for (var b : rawBuckets) {
            rawMap.put(b.bucketTime(), b);
        }

        // Generate complete continuous time sequence from windowStart to now
        List<ObservationTimeBucket> continuousBuckets = new ArrayList<>();
        ChronoUnit stepUnit = safeBucket.equals("1d") ? ChronoUnit.DAYS : ChronoUnit.HOURS;
        Instant current = windowStart.truncatedTo(stepUnit);
        Instant endTrunc = now.truncatedTo(stepUnit);

        long totalRequestsInWindow = 0;

        while (!current.isAfter(endTrunc)) {
            Instant next = current.plus(1, stepUnit);
            ApiDiscoveryRepository.RawObservationBucket raw = rawMap.get(current);

            if (raw != null) {
                totalRequestsInWindow += raw.requestCount();
                continuousBuckets.add(new ObservationTimeBucket(
                    current,
                    next,
                    raw.requestCount(),
                    raw.count2xx(),
                    raw.count3xx(),
                    raw.count4xx(),
                    raw.count5xx(),
                    raw.avgLatency(),
                    raw.minLatency(),
                    raw.maxLatency()
                ));
            } else {
                // Zero-filled missing interval (missing traffic != deletion)
                continuousBuckets.add(new ObservationTimeBucket(
                    current,
                    next,
                    0L,
                    0L,
                    0L,
                    0L,
                    0L,
                    null,
                    null,
                    null
                ));
            }
            current = next;
        }

        return Optional.of(new EndpointObservationHistoryResponse(
            ep.id(),
            ep.httpMethod(),
            ep.routeTemplate(),
            safeHours,
            safeBucket,
            windowStart,
            now,
            totalRequestsInWindow,
            continuousBuckets,
            720 // max retention limit hours
        ));
    }

    /**
     * Retrieves recent security and anomaly telemetry events and linked incident context for an endpoint.
     */
    public Optional<EndpointSecurityHistoryResponse> getEndpointSecurityHistory(String endpointId, Integer windowHours) {
        Optional<DiscoveredEndpointResponse> epOpt = getEndpointById(endpointId);
        if (epOpt.isEmpty()) {
            return Optional.empty();
        }

        DiscoveredEndpointResponse ep = epOpt.get();
        int safeHours = (windowHours != null && windowHours >= 1 && windowHours <= 720) ? windowHours : 24;
        Instant now = Instant.now();
        Instant windowStart = now.minus(Duration.ofHours(safeHours));

        ApiDiscoveryRepository.SecurityCounts secCounts = discoveryRepository.findSecurityCountsForEndpoint(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now
        );

        List<Integer> distinctStatuses = discoveryRepository.findDistinctStatusCodesForRoute(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now
        );
        if (distinctStatuses.isEmpty()) {
            distinctStatuses = ep.distinctStatusCodes();
        }

        List<EndpointSecurityEvent> securityEvents = discoveryRepository.findSecurityEventsForEndpoint(
            ep.httpMethod(), ep.routeTemplate(), windowStart, now, 50
        );

        List<EndpointLinkedIncident> linkedIncidents = discoveryRepository.findLinkedIncidentsForEndpoint(
            ep.serviceName(), ep.routeTemplate(), windowStart, now
        );

        return Optional.of(new EndpointSecurityHistoryResponse(
            ep.id(),
            ep.httpMethod(),
            ep.routeTemplate(),
            safeHours,
            windowStart,
            now,
            secCounts.authFailures(),
            secCounts.anomalyEvents(),
            distinctStatuses,
            securityEvents,
            linkedIncidents
        ));
    }

    private List<DiscoveredEndpointResponse> aggregateAndConsolidateEndpoints(String httpMethodFilter) {
        List<ApiDiscoveryRepository.RawEndpointAggregate> rawAggregates = 
            discoveryRepository.findObservedEndpointAggregates(httpMethodFilter);

        Map<String, Set<Integer>> statusCodesByEndpoint = new HashMap<>();
        try {
            List<ApiDiscoveryRepository.RouteStatusCode> routeStatuses = discoveryRepository.findDistinctStatusCodes();
            for (var rs : routeStatuses) {
                String normalized = RouteNormalizer.normalize(rs.endpointRoute());
                String key = rs.httpMethod().toUpperCase() + ":" + normalized;
                statusCodesByEndpoint.computeIfAbsent(key, k -> new TreeSet<>()).add(rs.statusCode());
            }
        } catch (Exception ignored) {
            // Distinct statuses are supplementary; continue even if distinct query fails
        }

        // Consolidate raw aggregates by canonical endpoint identity (METHOD + normalized route template)
        Map<String, MutableEndpoint> consolidated = new LinkedHashMap<>();

        for (var raw : rawAggregates) {
            String method = raw.httpMethod() != null ? raw.httpMethod().toUpperCase().trim() : "GET";
            String normalizedTemplate = RouteNormalizer.normalize(raw.endpointRoute());
            String key = method + ":" + normalizedTemplate;

            MutableEndpoint ep = consolidated.computeIfAbsent(key, k -> new MutableEndpoint(
                method,
                normalizedTemplate,
                RouteNormalizer.resolveService(normalizedTemplate)
            ));

            ep.merge(
                raw.totalRequests(),
                raw.firstObserved(),
                raw.lastObserved(),
                raw.avgLatency(),
                raw.count2xx(),
                raw.count3xx(),
                raw.count4xx(),
                raw.count5xx()
            );
        }

        List<DiscoveredEndpointResponse> result = new ArrayList<>(consolidated.size());
        for (var entry : consolidated.entrySet()) {
            MutableEndpoint m = entry.getValue();
            Set<Integer> statuses = statusCodesByEndpoint.getOrDefault(entry.getKey(), Collections.emptySet());

            Map<String, Long> statusDistribution = new LinkedHashMap<>();
            statusDistribution.put("2xx", m.count2xx);
            statusDistribution.put("3xx", m.count3xx);
            statusDistribution.put("4xx", m.count4xx);
            statusDistribution.put("5xx", m.count5xx);

            String endpointId = RouteNormalizer.generateEndpointId(m.httpMethod, m.routeTemplate);

            result.add(new DiscoveredEndpointResponse(
                endpointId,
                m.httpMethod,
                m.routeTemplate,
                m.serviceName,
                m.firstObserved,
                m.lastObserved,
                m.totalRequests,
                statusDistribution,
                new ArrayList<>(statuses),
                m.calculateAverageLatency()
            ));
        }

        return result;
    }

    private Comparator<DiscoveredEndpointResponse> getComparator(String sortBy, String sortDirection) {
        boolean desc = sortDirection == null || !sortDirection.equalsIgnoreCase("ASC");
        Comparator<DiscoveredEndpointResponse> comp;

        if ("totalRequests".equalsIgnoreCase(sortBy) || "requests".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparingLong(DiscoveredEndpointResponse::totalRequests);
        } else if ("routeTemplate".equalsIgnoreCase(sortBy) || "path".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(DiscoveredEndpointResponse::routeTemplate, String.CASE_INSENSITIVE_ORDER);
        } else if ("serviceName".equalsIgnoreCase(sortBy) || "service".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(DiscoveredEndpointResponse::serviceName, String.CASE_INSENSITIVE_ORDER);
        } else if ("httpMethod".equalsIgnoreCase(sortBy) || "method".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(DiscoveredEndpointResponse::httpMethod, String.CASE_INSENSITIVE_ORDER);
        } else if ("firstObserved".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(DiscoveredEndpointResponse::firstObservedAt);
        } else {
            // Default: lastObserved
            comp = Comparator.comparing(DiscoveredEndpointResponse::lastObservedAt);
        }

        return desc ? comp.reversed() : comp;
    }

    private static class MutableEndpoint {
        final String httpMethod;
        final String routeTemplate;
        final String serviceName;
        long totalRequests = 0L;
        Instant firstObserved = Instant.MAX;
        Instant lastObserved = Instant.MIN;
        long count2xx = 0L;
        long count3xx = 0L;
        long count4xx = 0L;
        long count5xx = 0L;
        double latencySum = 0.0;
        long latencyCount = 0L;

        MutableEndpoint(String httpMethod, String routeTemplate, String serviceName) {
            this.httpMethod = httpMethod;
            this.routeTemplate = routeTemplate;
            this.serviceName = serviceName;
        }

        void merge(long requests, Instant first, Instant last, Double avgLat,
                   long c2, long c3, long c4, long c5) {
            this.totalRequests += requests;
            if (first != null && first.isBefore(this.firstObserved)) {
                this.firstObserved = first;
            }
            if (last != null && last.isAfter(this.lastObserved)) {
                this.lastObserved = last;
            }
            this.count2xx += c2;
            this.count3xx += c3;
            this.count4xx += c4;
            this.count5xx += c5;
            if (avgLat != null && requests > 0) {
                this.latencySum += (avgLat * requests);
                this.latencyCount += requests;
            }
        }

        Double calculateAverageLatency() {
            if (latencyCount == 0) return 0.0;
            return Math.round((latencySum / latencyCount) * 10.0) / 10.0;
        }
    }
}
