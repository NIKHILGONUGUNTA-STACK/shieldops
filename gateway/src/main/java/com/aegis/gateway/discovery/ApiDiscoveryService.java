package com.aegis.gateway.discovery;

import com.aegis.gateway.discovery.dto.DiscoveredEndpointPageResponse;
import com.aegis.gateway.discovery.dto.DiscoveredEndpointResponse;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for consolidating wire telemetry into an inventory of observed API endpoints.
 */
@Service
public class ApiDiscoveryService {

    private final ApiDiscoveryRepository discoveryRepository;

    public ApiDiscoveryService(ApiDiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
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
