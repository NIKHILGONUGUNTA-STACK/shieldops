package com.aegis.gateway.reconciliation;

import com.aegis.gateway.discovery.RouteNormalizer;
import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationItemResponse;
import com.aegis.gateway.reconciliation.dto.ReconciliationPageResponse;
import com.aegis.gateway.reconciliation.dto.ReconciliationSummaryResponse;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for reconciling declared OpenAPI specifications against live passive wire telemetry.
 * Enforces canonical operation identity, deterministic category precedence, and bounded observation windows.
 */
@Service
public class ApiReconciliationService {

    private static final int DEFAULT_WINDOW_HOURS = 24;
    private static final int MAX_WINDOW_HOURS = 720; // 30 days
    private static final int MIN_WINDOW_HOURS = 1;

    private final ApiReconciliationRepository reconciliationRepository;

    public ApiReconciliationService(ApiReconciliationRepository reconciliationRepository) {
        this.reconciliationRepository = reconciliationRepository;
    }

    public record WindowBoundaries(Instant start, Instant end, int hours) {}

    /**
     * Reconciles documented OpenAPI contracts against passive gateway wire telemetry.
     */
    public ReconciliationPageResponse reconcile(
            int page,
            int size,
            UUID specificationId,
            String serviceName,
            String httpMethod,
            String categoryStr,
            Integer windowHours,
            Instant from,
            Instant to,
            String search,
            String sortBy,
            String sortDirection) {

        WindowBoundaries window = resolveWindow(windowHours, from, to);
        ReconciliationCategory filterCategory = parseCategory(categoryStr);

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);

        // 1. Fetch raw declared operations and raw telemetry aggregates
        List<ApiReconciliationRepository.RawDeclaredOperation> declaredOps =
            reconciliationRepository.findDeclaredOperations(specificationId);

        List<ApiReconciliationRepository.RawObservedOperation> observedOps =
            reconciliationRepository.findObservedOperationsInWindow(window.start(), window.end(), httpMethod);

        // 2. Perform reconciliation evaluation
        List<ReconciliationItemResponse> allItems = evaluateReconciliation(
            declaredOps,
            observedOps,
            window,
            specificationId
        );

        // 3. Compute summary across all items before page slicing
        ReconciliationSummaryResponse summary = buildSummary(allItems, window, specificationId);

        // 4. Apply filters
        List<ReconciliationItemResponse> filtered = allItems.stream()
            .filter(item -> {
                if (filterCategory != null && item.category() != filterCategory) {
                    return false;
                }
                if (serviceName != null && !serviceName.isBlank()) {
                    if (!item.serviceBoundary().equalsIgnoreCase(serviceName.trim())) {
                        return false;
                    }
                }
                if (httpMethod != null && !httpMethod.isBlank()) {
                    if (!item.httpMethod().equalsIgnoreCase(httpMethod.trim())) {
                        return false;
                    }
                }
                if (search != null && !search.isBlank()) {
                    String q = search.toLowerCase().trim();
                    boolean matchRoute = item.normalizedRoute().toLowerCase().contains(q);
                    boolean matchService = item.serviceBoundary().toLowerCase().contains(q);
                    boolean matchMethod = item.httpMethod().toLowerCase().contains(q);
                    boolean matchSpec = item.specificationName() != null && item.specificationName().toLowerCase().contains(q);
                    boolean matchOpId = item.operationId() != null && item.operationId().toLowerCase().contains(q);
                    if (!matchRoute && !matchService && !matchMethod && !matchSpec && !matchOpId) {
                        return false;
                    }
                }
                return true;
            })
            .collect(Collectors.toList());

        // 5. Sort results deterministically
        filtered.sort(getComparator(sortBy, sortDirection));

        // 6. Paginate
        long totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);
        int offset = boundedPage * boundedSize;

        List<ReconciliationItemResponse> pagedContent;
        if (offset >= totalElements) {
            pagedContent = Collections.emptyList();
        } else {
            int toIndex = Math.min(offset + boundedSize, (int) totalElements);
            pagedContent = filtered.subList(offset, toIndex);
        }

        boolean hasNext = boundedPage < (totalPages - 1);
        boolean hasPrevious = boundedPage > 0 && totalPages > 0;

        return new ReconciliationPageResponse(
            pagedContent,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            hasNext,
            hasPrevious,
            summary
        );
    }

    /**
     * Returns reconciliation summary metrics for a given scope and observation window.
     */
    public ReconciliationSummaryResponse getSummary(
            UUID specificationId,
            Integer windowHours,
            Instant from,
            Instant to) {

        WindowBoundaries window = resolveWindow(windowHours, from, to);

        List<ApiReconciliationRepository.RawDeclaredOperation> declaredOps =
            reconciliationRepository.findDeclaredOperations(specificationId);

        List<ApiReconciliationRepository.RawObservedOperation> observedOps =
            reconciliationRepository.findObservedOperationsInWindow(window.start(), window.end(), null);

        List<ReconciliationItemResponse> allItems = evaluateReconciliation(
            declaredOps,
            observedOps,
            window,
            specificationId
        );

        return buildSummary(allItems, window, specificationId);
    }

    /**
     * Pure reconciliation evaluation core: compares declared and observed operations.
     */
    List<ReconciliationItemResponse> evaluateReconciliation(
            List<ApiReconciliationRepository.RawDeclaredOperation> declaredOps,
            List<ApiReconciliationRepository.RawObservedOperation> observedOps,
            WindowBoundaries window,
            UUID selectedSpecId) {

        // Index declared operations by canonical key (METHOD:ROUTE)
        // A route might have multiple declared methods (e.g. GET and POST)
        Map<String, List<ApiReconciliationRepository.RawDeclaredOperation>> declaredByKey = new LinkedHashMap<>();
        Map<String, Set<String>> declaredMethodsByRoute = new HashMap<>();

        for (var dec : declaredOps) {
            String method = dec.httpMethod().toUpperCase().trim();
            String route = RouteNormalizer.normalize(dec.normalizedRoute());
            String key = method + ":" + route;

            declaredByKey.computeIfAbsent(key, k -> new ArrayList<>()).add(dec);
            declaredMethodsByRoute.computeIfAbsent(route, r -> new LinkedHashSet<>()).add(method);
        }

        // Aggregate and normalize observed operations by canonical key (METHOD:ROUTE)
        Map<String, MutableObserved> observedByKey = new LinkedHashMap<>();
        Map<String, Set<String>> observedMethodsByRoute = new HashMap<>();

        for (var obs : observedOps) {
            String method = obs.httpMethod().toUpperCase().trim();
            String route = RouteNormalizer.normalize(obs.endpointRoute());
            String key = method + ":" + route;

            MutableObserved m = observedByKey.computeIfAbsent(key, k -> new MutableObserved(method, route));
            m.merge(
                obs.totalRequests(),
                obs.firstObserved(),
                obs.lastObserved(),
                obs.count2xx(),
                obs.count3xx(),
                obs.count4xx(),
                obs.count5xx()
            );

            observedMethodsByRoute.computeIfAbsent(route, r -> new LinkedHashSet<>()).add(method);
        }

        // Canonical keys union
        Set<String> allKeys = new LinkedHashSet<>();
        allKeys.addAll(declaredByKey.keySet());
        allKeys.addAll(observedByKey.keySet());

        List<ReconciliationItemResponse> results = new ArrayList<>(allKeys.size());

        for (String key : allKeys) {
            int colonIdx = key.indexOf(':');
            String method = key.substring(0, colonIdx);
            String route = key.substring(colonIdx + 1);

            List<ApiReconciliationRepository.RawDeclaredOperation> decList = declaredByKey.get(key);
            MutableObserved obs = observedByKey.get(key);

            boolean isDeclared = decList != null && !decList.isEmpty();
            boolean isObserved = obs != null && obs.totalRequests > 0;

            Set<String> declMethods = declaredMethodsByRoute.getOrDefault(route, Collections.emptySet());
            Set<String> obsMethods = observedMethodsByRoute.getOrDefault(route, Collections.emptySet());

            // Check for ambiguity across overlapping specs
            boolean isAmbiguous = false;
            if (isDeclared && decList.size() > 1 && selectedSpecId == null) {
                // Multiple specs declare this exact method and route with different service boundaries or definitions
                Set<String> distinctServices = decList.stream()
                    .map(ApiReconciliationRepository.RawDeclaredOperation::serviceBoundary)
                    .collect(Collectors.toSet());
                if (distinctServices.size() > 1) {
                    isAmbiguous = true;
                }
            }

            ReconciliationCategory category;
            String explanation;

            if (isAmbiguous) {
                category = ReconciliationCategory.AMBIGUOUS;
                String specNames = decList.stream()
                    .map(d -> d.specificationName() + " (v" + d.specificationVersion() + ")")
                    .distinct()
                    .collect(Collectors.joining(", "));
                explanation = String.format(
                    "Route %s is declared ambiguously across multiple specifications with conflicting service boundaries: %s",
                    route, specNames
                );
            } else if (isDeclared && isObserved) {
                category = ReconciliationCategory.MATCHED;
                ApiReconciliationRepository.RawDeclaredOperation primaryDec = decList.get(0);
                explanation = String.format(
                    "Declared in specification '%s' (v%s) and observed with %d requests during the %dh monitoring window.",
                    primaryDec.specificationName(), primaryDec.specificationVersion(), obs.totalRequests, window.hours()
                );
            } else if (isObserved && !isDeclared) {
                if (!declMethods.isEmpty()) {
                    category = ReconciliationCategory.METHOD_MISMATCH;
                    explanation = String.format(
                        "Observed HTTP %s on route %s, but specification declares methods: %s.",
                        method, route, declMethods
                    );
                } else {
                    category = ReconciliationCategory.OBSERVED_UNDOCUMENTED;
                    explanation = String.format(
                        "Observed %d requests on route %s, which is not declared in the active specification inventory.",
                        obs.totalRequests, route
                    );
                }
            } else { // isDeclared && !isObserved
                category = ReconciliationCategory.DOCUMENTED_UNOBSERVED;
                ApiReconciliationRepository.RawDeclaredOperation primaryDec = decList.get(0);
                explanation = String.format(
                    "Declared in specification '%s' (v%s), but no wire telemetry was observed within the %dh monitoring window.",
                    primaryDec.specificationName(), primaryDec.specificationVersion(), window.hours()
                );
            }

            // Provenance assembly
            ApiReconciliationRepository.RawDeclaredOperation dec = isDeclared ? decList.get(0) : null;
            String pathPattern = dec != null ? dec.pathPattern() : route;
            UUID specId = dec != null ? dec.specificationId() : null;
            String specName = dec != null ? dec.specificationName() : null;
            String specVer = dec != null ? dec.specificationVersion() : null;
            String opId = dec != null ? dec.openApiOperationId() : null;
            String service = dec != null ? dec.serviceBoundary() : RouteNormalizer.resolveService(route);

            Instant firstObs = obs != null ? obs.firstObserved : null;
            Instant lastObs = obs != null ? obs.lastObserved : null;
            long totalReqs = obs != null ? obs.totalRequests : 0L;

            Map<String, Long> statusDist = new LinkedHashMap<>();
            if (obs != null) {
                statusDist.put("2xx", obs.count2xx);
                statusDist.put("3xx", obs.count3xx);
                statusDist.put("4xx", obs.count4xx);
                statusDist.put("5xx", obs.count5xx);
            }

            String stableId = generateStableId(method, route, specId);

            results.add(new ReconciliationItemResponse(
                stableId,
                method,
                route,
                pathPattern,
                category,
                specId,
                specName,
                specVer,
                opId,
                service,
                firstObs,
                lastObs,
                totalReqs,
                statusDist,
                new ArrayList<>(declMethods),
                new ArrayList<>(obsMethods),
                window.start(),
                window.end(),
                explanation
            ));
        }

        return results;
    }

    private ReconciliationSummaryResponse buildSummary(
            List<ReconciliationItemResponse> items,
            WindowBoundaries window,
            UUID specId) {

        long matched = 0;
        long undocumented = 0;
        long unobserved = 0;
        long methodMismatch = 0;
        long ambiguous = 0;

        for (var item : items) {
            switch (item.category()) {
                case MATCHED -> matched++;
                case OBSERVED_UNDOCUMENTED -> undocumented++;
                case DOCUMENTED_UNOBSERVED -> unobserved++;
                case METHOD_MISMATCH -> methodMismatch++;
                case AMBIGUOUS -> ambiguous++;
            }
        }

        long totalEvaluated = items.size();
        long totalDeclared = matched + unobserved;
        double coverage = totalDeclared > 0
            ? Math.round(((double) matched / totalDeclared) * 1000.0) / 10.0
            : 0.0;

        String specName = null;
        if (specId != null) {
            specName = reconciliationRepository.findSpecificationName(specId).orElse("Selected Specification");
        }

        return new ReconciliationSummaryResponse(
            matched,
            undocumented,
            unobserved,
            methodMismatch,
            ambiguous,
            totalEvaluated,
            coverage,
            window.hours(),
            window.start(),
            window.end(),
            specId,
            specName
        );
    }

    public WindowBoundaries resolveWindow(Integer windowHours, Instant from, Instant to) {
        if (from != null && to != null) {
            if (from.isAfter(to)) {
                throw new IllegalArgumentException("Invalid observation window: 'from' must be before or equal to 'to'");
            }
            long hoursBetween = Duration.between(from, to).toHours();
            if (hoursBetween > MAX_WINDOW_HOURS) {
                throw new IllegalArgumentException("Observation window exceeds maximum retention limit of " + MAX_WINDOW_HOURS + " hours (30 days)");
            }
            return new WindowBoundaries(from, to, (int) Math.max(1, hoursBetween));
        }

        int hours = windowHours != null ? windowHours : DEFAULT_WINDOW_HOURS;
        if (hours < MIN_WINDOW_HOURS || hours > MAX_WINDOW_HOURS) {
            throw new IllegalArgumentException("windowHours must be between " + MIN_WINDOW_HOURS + " and " + MAX_WINDOW_HOURS);
        }

        Instant end = Instant.now();
        Instant start = end.minus(hours, ChronoUnit.HOURS);
        return new WindowBoundaries(start, end, hours);
    }

    private ReconciliationCategory parseCategory(String categoryStr) {
        if (categoryStr == null || categoryStr.isBlank()) {
            return null;
        }
        try {
            return ReconciliationCategory.valueOf(categoryStr.toUpperCase().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid reconciliation category: " + categoryStr + ". Accepted: MATCHED, OBSERVED_UNDOCUMENTED, DOCUMENTED_UNOBSERVED, METHOD_MISMATCH, AMBIGUOUS");
        }
    }

    private Comparator<ReconciliationItemResponse> getComparator(String sortBy, String sortDirection) {
        boolean desc = sortDirection == null || !sortDirection.equalsIgnoreCase("ASC");
        Comparator<ReconciliationItemResponse> comp;

        if ("requests".equalsIgnoreCase(sortBy) || "totalRequests".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparingLong(ReconciliationItemResponse::totalRequests);
        } else if ("route".equalsIgnoreCase(sortBy) || "normalizedRoute".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(ReconciliationItemResponse::normalizedRoute, String.CASE_INSENSITIVE_ORDER);
        } else if ("method".equalsIgnoreCase(sortBy) || "httpMethod".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(ReconciliationItemResponse::httpMethod, String.CASE_INSENSITIVE_ORDER);
        } else if ("service".equalsIgnoreCase(sortBy) || "serviceBoundary".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(ReconciliationItemResponse::serviceBoundary, String.CASE_INSENSITIVE_ORDER);
        } else if ("lastObserved".equalsIgnoreCase(sortBy) || "lastObservedAt".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(
                ReconciliationItemResponse::lastObservedAt,
                Comparator.nullsLast(Comparator.naturalOrder())
            );
        } else {
            // Default: Category precedence
            comp = Comparator.comparing(item -> item.category().ordinal());
        }

        return desc ? comp.reversed() : comp;
    }

    private String generateStableId(String method, String route, UUID specId) {
        String raw = method + ":" + route + ":" + (specId != null ? specId : "global");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return "rec_" + HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (Exception e) {
            return "rec_" + Integer.toHexString(raw.hashCode());
        }
    }

    private static class MutableObserved {
        final String httpMethod;
        final String routeTemplate;
        long totalRequests = 0;
        Instant firstObserved = null;
        Instant lastObserved = null;
        long count2xx = 0;
        long count3xx = 0;
        long count4xx = 0;
        long count5xx = 0;

        MutableObserved(String httpMethod, String routeTemplate) {
            this.httpMethod = httpMethod;
            this.routeTemplate = routeTemplate;
        }

        void merge(long reqs, Instant first, Instant last, long c2, long c3, long c4, long c5) {
            this.totalRequests += reqs;
            if (this.firstObserved == null || (first != null && first.isBefore(this.firstObserved))) {
                this.firstObserved = first;
            }
            if (this.lastObserved == null || (last != null && last.isAfter(this.lastObserved))) {
                this.lastObserved = last;
            }
            this.count2xx += c2;
            this.count3xx += c3;
            this.count4xx += c4;
            this.count5xx += c5;
        }
    }
}

