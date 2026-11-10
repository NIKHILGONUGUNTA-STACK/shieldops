package com.aegis.gateway.classification;

import com.aegis.gateway.discovery.ApiDiscoveryRepository;
import com.aegis.gateway.discovery.RouteNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Deterministic, explainable Sensitive Data Classification Engine for Aegis.
 * Maps observed and declared API fields to sensitivity levels (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
 * based on approved API schemas and field-level metadata without guessing or inferring from route names alone.
 */
@Service
public class SensitiveDataClassificationEngine {

    private static final Logger log = LoggerFactory.getLogger(SensitiveDataClassificationEngine.class);
    public static final String POLICY_VERSION = "v1.0.0";

    private final ApiDiscoveryRepository discoveryRepository;

    // Rule storage: key = "METHOD:ROUTE_TEMPLATE" -> Map<fieldPath, FieldClassification>
    private final Map<String, Map<String, FieldClassification>> classificationRules = new ConcurrentHashMap<>();

    @Autowired
    public SensitiveDataClassificationEngine(@Autowired(required = false) ApiDiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
        initializeBaselineRules();
    }

    /**
     * Registers a deterministic field-level classification rule.
     * Enforces conflict resolution: if a rule already exists for the field,
     * the higher sensitivity level takes precedence.
     */
    public synchronized void registerRule(FieldClassification rule) {
        if (rule == null || rule.httpMethod() == null || rule.routeTemplate() == null || rule.fieldPath() == null) {
            return;
        }

        String endpointKey = buildEndpointKey(rule.httpMethod(), rule.routeTemplate());
        Map<String, FieldClassification> fieldMap = classificationRules.computeIfAbsent(endpointKey, k -> new ConcurrentHashMap<>());

        String normalizedField = normalizeFieldPath(rule.fieldPath());
        FieldClassification existing = fieldMap.get(normalizedField);

        if (existing == null) {
            fieldMap.put(normalizedField, rule);
        } else {
            // Conflict resolution: higher sensitivity level takes precedence
            if (rule.dataClassification().isHigherThan(existing.dataClassification())) {
                log.debug("Conflict resolved for {}: upgraded {} -> {}",
                    normalizedField, existing.dataClassification(), rule.dataClassification());
                fieldMap.put(normalizedField, rule);
            } else if (existing.dataClassification().isHigherThan(rule.dataClassification())) {
                log.debug("Conflict resolved for {}: retained higher sensitivity {}",
                    normalizedField, existing.dataClassification());
            } else {
                // Same sensitivity level: update with higher confidence if applicable
                fieldMap.put(normalizedField, rule);
            }
        }
    }

    /**
     * Classifies a specific field on an endpoint.
     */
    public FieldClassification classifyField(String serviceBoundary, String httpMethod, String routeTemplate, String fieldPath) {
        String endpointKey = buildEndpointKey(httpMethod, routeTemplate);
        Map<String, FieldClassification> fieldMap = classificationRules.get(endpointKey);

        String normalizedField = normalizeFieldPath(fieldPath);

        if (fieldMap != null) {
            // 1. Exact match
            if (fieldMap.containsKey(normalizedField)) {
                return fieldMap.get(normalizedField);
            }

            // 2. Wildcard / hierarchy match (e.g. "customer.*" matches "customer.email")
            for (Map.Entry<String, FieldClassification> entry : fieldMap.entrySet()) {
                String rulePath = entry.getKey();
                if (matchesFieldPattern(rulePath, normalizedField)) {
                    FieldClassification base = entry.getValue();
                    return new FieldClassification(
                        serviceBoundary != null ? serviceBoundary : base.serviceBoundary(),
                        httpMethod,
                        routeTemplate,
                        normalizedField,
                        base.dataClassification(),
                        base.classificationRationale(),
                        base.approvedAccessRoles(),
                        base.resourceOwnershipRequirements(),
                        base.schemaSource(),
                        base.confidence(),
                        base.policyVersion(),
                        base.manualReviewRequired()
                    );
                }
            }
        }

        // 3. Unknown field: classified with UNKNOWN confidence requiring manual review
        return new FieldClassification(
            serviceBoundary != null ? serviceBoundary : "unknown",
            httpMethod,
            routeTemplate,
            normalizedField,
            DataSensitivityLevel.INTERNAL,
            "Unclassified response field absent from authoritative schema; provisional internal classification",
            Set.of("SECURITY_ANALYST", "SECURITY_ADMIN"),
            ResourceOwnershipRequirement.NONE,
            "UNCLASSIFIED_OBSERVATION",
            ClassificationConfidence.UNKNOWN,
            POLICY_VERSION,
            true
        );
    }

    /**
     * Produces an endpoint-level consolidated classification dossier.
     */
    public EndpointDataClassification classifyEndpoint(String endpointId, String httpMethod, String routeTemplate, String serviceBoundary) {
        String key = buildEndpointKey(httpMethod, routeTemplate);
        Map<String, FieldClassification> declaredFields = classificationRules.getOrDefault(key, Collections.emptyMap());

        List<FieldClassification> fieldList = new ArrayList<>(declaredFields.values());
        fieldList.sort(Comparator.comparing(FieldClassification::fieldPath));

        int totalFields = fieldList.size();
        int classifiedCount = 0;
        int unclassifiedCount = 0;
        DataSensitivityLevel highest = DataSensitivityLevel.PUBLIC;
        boolean manualReview = false;

        for (FieldClassification fc : fieldList) {
            if (fc.confidence() == ClassificationConfidence.UNKNOWN || fc.manualReviewRequired()) {
                unclassifiedCount++;
                manualReview = true;
            } else {
                classifiedCount++;
            }
            highest = DataSensitivityLevel.highest(highest, fc.dataClassification());
        }

        double coverage = totalFields > 0
            ? BigDecimal.valueOf((double) classifiedCount / totalFields * 100.0)
                .setScale(1, RoundingMode.HALF_UP).doubleValue()
            : 0.0;

        String id = endpointId != null ? endpointId : computeEndpointId(httpMethod, routeTemplate);

        return new EndpointDataClassification(
            id,
            httpMethod,
            routeTemplate,
            serviceBoundary,
            highest,
            totalFields,
            classifiedCount,
            unclassifiedCount,
            fieldList,
            coverage,
            manualReview,
            Instant.now()
        );
    }

    /**
     * Returns paginated sensitive data classification inventory across all known/discovered endpoints.
     */
    public SensitiveDataInventoryPageResponse getInventory(
            int page,
            int size,
            String serviceName,
            String sensitivity,
            Boolean manualReviewRequired,
            String search,
            String sortBy,
            String sortDirection) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);

        List<EndpointDataClassification> all = getAllEndpointClassifications();

        // Apply filters
        List<EndpointDataClassification> filtered = all.stream()
            .filter(ep -> {
                if (serviceName != null && !serviceName.isBlank()) {
                    if (!ep.serviceBoundary().equalsIgnoreCase(serviceName.trim())) {
                        return false;
                    }
                }
                if (sensitivity != null && !sensitivity.isBlank()) {
                    if (!ep.highestSensitivityLevel().name().equalsIgnoreCase(sensitivity.trim())) {
                        return false;
                    }
                }
                if (manualReviewRequired != null) {
                    if (ep.manualReviewRequired() != manualReviewRequired) {
                        return false;
                    }
                }
                if (search != null && !search.isBlank()) {
                    String q = search.toLowerCase().trim();
                    boolean mRoute = ep.routeTemplate().toLowerCase().contains(q);
                    boolean mService = ep.serviceBoundary().toLowerCase().contains(q);
                    boolean mMethod = ep.httpMethod().toLowerCase().contains(q);
                    boolean mFields = ep.fieldClassifications().stream().anyMatch(f -> f.fieldPath().toLowerCase().contains(q));
                    if (!mRoute && !mService && !mMethod && !mFields) {
                        return false;
                    }
                }
                return true;
            })
            .collect(Collectors.toList());

        // Sort
        Comparator<EndpointDataClassification> comparator = getComparator(sortBy, sortDirection);
        filtered.sort(comparator);

        // Paginate
        long totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);
        int offset = boundedPage * boundedSize;

        List<EndpointDataClassification> pagedContent;
        if (offset >= totalElements) {
            pagedContent = Collections.emptyList();
        } else {
            int toIndex = Math.min(offset + boundedSize, (int) totalElements);
            pagedContent = filtered.subList(offset, toIndex);
        }

        return new SensitiveDataInventoryPageResponse(
            pagedContent,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            boundedPage < (totalPages - 1),
            boundedPage > 0 && totalPages > 0
        );
    }

    /**
     * Returns platform-level sensitive data classification summary metrics.
     */
    public SensitiveDataInventorySummary getSummary() {
        List<EndpointDataClassification> all = getAllEndpointClassifications();

        long totalEndpoints = all.size();
        long totalClassified = 0;
        long totalUnclassified = 0;
        long totalFields = 0;

        Map<DataSensitivityLevel, Long> countsBySensitivity = new EnumMap<>(DataSensitivityLevel.class);
        for (DataSensitivityLevel level : DataSensitivityLevel.values()) {
            countsBySensitivity.put(level, 0L);
        }

        Map<String, List<EndpointDataClassification>> byService = new HashMap<>();

        for (EndpointDataClassification ep : all) {
            totalClassified += ep.classifiedFieldsCount();
            totalUnclassified += ep.unclassifiedFieldsCount();
            totalFields += ep.totalFields();

            countsBySensitivity.put(
                ep.highestSensitivityLevel(),
                countsBySensitivity.getOrDefault(ep.highestSensitivityLevel(), 0L) + 1
            );

            byService.computeIfAbsent(ep.serviceBoundary(), k -> new ArrayList<>()).add(ep);
        }

        double overallCoverage = totalFields > 0
            ? BigDecimal.valueOf((double) totalClassified / totalFields * 100.0)
                .setScale(1, RoundingMode.HALF_UP).doubleValue()
            : 0.0;

        Map<String, ServiceClassificationSummary> serviceWise = new TreeMap<>();
        for (Map.Entry<String, List<EndpointDataClassification>> entry : byService.entrySet()) {
            String service = entry.getKey();
            List<EndpointDataClassification> epList = entry.getValue();

            long sTotalEp = epList.size();
            long sClassified = epList.stream().mapToLong(EndpointDataClassification::classifiedFieldsCount).sum();
            long sUnclassified = epList.stream().mapToLong(EndpointDataClassification::unclassifiedFieldsCount).sum();
            long sTotalFields = epList.stream().mapToLong(EndpointDataClassification::totalFields).sum();

            double sCoverage = sTotalFields > 0
                ? BigDecimal.valueOf((double) sClassified / sTotalFields * 100.0)
                    .setScale(1, RoundingMode.HALF_UP).doubleValue()
                : 0.0;

            serviceWise.put(service, new ServiceClassificationSummary(
                service, sTotalEp, sClassified, sUnclassified, sTotalFields, sCoverage
            ));
        }

        return new SensitiveDataInventorySummary(
            totalEndpoints,
            totalClassified,
            totalUnclassified,
            totalFields,
            overallCoverage,
            countsBySensitivity,
            serviceWise,
            POLICY_VERSION,
            Instant.now()
        );
    }

    /**
     * Retrieves classification details for a single endpoint by its ID.
     */
    public Optional<EndpointDataClassification> getEndpointDetails(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        return getAllEndpointClassifications().stream()
            .filter(ep -> ep.id().equalsIgnoreCase(id.trim()))
            .findFirst();
    }

    /**
     * Redacts a sensitive field value according to its classification level.
     * RESTRICTED: fully masked.
     * CONFIDENTIAL: structural masked.
     * INTERNAL / PUBLIC: unredacted or minimal mask.
     */
    public String redactValue(String fieldPath, Object rawValue, DataSensitivityLevel level) {
        if (rawValue == null) {
            return null;
        }
        String str = rawValue.toString();
        if (str.isBlank()) {
            return str;
        }

        if (level == DataSensitivityLevel.RESTRICTED) {
            return "[REDACTED_RESTRICTED]";
        }

        if (level == DataSensitivityLevel.CONFIDENTIAL) {
            String path = fieldPath.toLowerCase();
            if (path.contains("email")) {
                int atIdx = str.indexOf('@');
                if (atIdx > 1) {
                    return str.charAt(0) + "***" + str.substring(atIdx);
                }
                return "***@***";
            }
            if (path.contains("account") || path.contains("reference") || path.contains("number")) {
                if (str.length() > 4) {
                    return "****" + str.substring(str.length() - 4);
                }
                return "****";
            }
            if (path.contains("balance") || path.contains("amount")) {
                return "***.**";
            }
            if (path.contains("name")) {
                return str.charAt(0) + "***";
            }
            return "[REDACTED_CONFIDENTIAL]";
        }

        return str;
    }

    private List<EndpointDataClassification> getAllEndpointClassifications() {
        // Collect endpoints from rule definitions first
        Map<String, EndpointDataClassification> consolidated = new LinkedHashMap<>();

        for (Map.Entry<String, Map<String, FieldClassification>> entry : classificationRules.entrySet()) {
            String endpointKey = entry.getKey();
            String[] parts = endpointKey.split(":", 2);
            String method = parts[0];
            String route = parts[1];

            // Determine service boundary from first rule
            String service = entry.getValue().values().stream()
                .map(FieldClassification::serviceBoundary)
                .findFirst().orElse("gateway");

            String epId = computeEndpointId(method, route);
            consolidated.put(epId, classifyEndpoint(epId, method, route, service));
        }

        // If discovery repository has additional endpoints, merge them in as provisional/unknown
        if (discoveryRepository != null) {
            try {
                List<ApiDiscoveryRepository.RawEndpointAggregate> rawAggs = discoveryRepository.findObservedEndpointAggregates(null);
                for (ApiDiscoveryRepository.RawEndpointAggregate raw : rawAggs) {
                    String routeTemplate = RouteNormalizer.normalize(raw.endpointRoute());
                    String method = raw.httpMethod() != null ? raw.httpMethod().toUpperCase().trim() : "GET";
                    String service = RouteNormalizer.resolveService(routeTemplate);
                    String epId = RouteNormalizer.generateEndpointId(method, routeTemplate);
                    if (!consolidated.containsKey(epId)) {
                        // Endpoint was observed on wire but has no declared rules yet
                        consolidated.put(epId, classifyEndpoint(epId, method, routeTemplate, service));
                    }
                }
            } catch (Exception e) {
                log.debug("Discovery repository endpoints lookup: {}", e.getMessage());
            }
        }

        return new ArrayList<>(consolidated.values());
    }

    private String buildEndpointKey(String method, String routeTemplate) {
        return (method != null ? method.toUpperCase().trim() : "*") + ":" +
               (routeTemplate != null ? routeTemplate.trim() : "/");
    }

    private String normalizeFieldPath(String fieldPath) {
        if (fieldPath == null) return "";
        return fieldPath.trim().replaceAll("^\\[\\]\\.", "");
    }

    private boolean matchesFieldPattern(String rulePattern, String fieldPath) {
        if (rulePattern.equals(fieldPath)) {
            return true;
        }
        if (rulePattern.endsWith(".*")) {
            String prefix = rulePattern.substring(0, rulePattern.length() - 2);
            return fieldPath.startsWith(prefix + ".") || fieldPath.equals(prefix);
        }
        return false;
    }

    private String computeEndpointId(String method, String routeTemplate) {
        return RouteNormalizer.generateEndpointId(method, routeTemplate);
    }

    private Comparator<EndpointDataClassification> getComparator(String sortBy, String sortDirection) {
        boolean asc = "asc".equalsIgnoreCase(sortDirection);
        Comparator<EndpointDataClassification> comp;

        if ("service".equalsIgnoreCase(sortBy) || "serviceBoundary".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparing(EndpointDataClassification::serviceBoundary, String.CASE_INSENSITIVE_ORDER);
        } else if ("sensitivity".equalsIgnoreCase(sortBy) || "highestSensitivityLevel".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparingInt(ep -> ep.highestSensitivityLevel().getRank());
        } else if ("coverage".equalsIgnoreCase(sortBy) || "coveragePercentage".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparingDouble(EndpointDataClassification::coveragePercentage);
        } else if ("fields".equalsIgnoreCase(sortBy) || "totalFields".equalsIgnoreCase(sortBy)) {
            comp = Comparator.comparingInt(EndpointDataClassification::totalFields);
        } else {
            comp = Comparator.comparing(EndpointDataClassification::routeTemplate, String.CASE_INSENSITIVE_ORDER);
        }

        return asc ? comp : comp.reversed();
    }

    /**
     * Initializes baseline deterministic rules across all approved Aegis FinTech schemas and platform routes.
     */
    private void initializeBaselineRules() {
        // =========================================================================
        // 1. Customer Service Endpoints & DTOs
        // =========================================================================
        String svcCustomer = "customer-service";

        // GET /api/v1/customers/{customerId} -> CustomerView
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "id",
            DataSensitivityLevel.CONFIDENTIAL, "Internal UUID identifier of customer entity",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "customerNumber",
            DataSensitivityLevel.CONFIDENTIAL, "Primary customer account number identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "firstName",
            DataSensitivityLevel.CONFIDENTIAL, "Customer legal first name (PII)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "lastName",
            DataSensitivityLevel.CONFIDENTIAL, "Customer legal last name (PII)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Customer standing and lifecycle state (ACTIVE, SUSPENDED, CLOSED)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}", "createdDate",
            DataSensitivityLevel.CONFIDENTIAL, "Customer relationship creation date",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // GET /api/v1/customers/{customerId}/profile -> CustomerProfile
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "id",
            DataSensitivityLevel.CONFIDENTIAL, "Internal UUID identifier of customer profile",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "customerNumber",
            DataSensitivityLevel.CONFIDENTIAL, "Primary customer identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "firstName",
            DataSensitivityLevel.CONFIDENTIAL, "Customer legal first name (PII)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "lastName",
            DataSensitivityLevel.CONFIDENTIAL, "Customer legal last name (PII)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "email",
            DataSensitivityLevel.CONFIDENTIAL, "Customer contact email address (Direct PII)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "countryCode",
            DataSensitivityLevel.CONFIDENTIAL, "Customer tax/residence jurisdiction country code",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcCustomer, "GET", "/api/v1/customers/{customerId}/profile", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Customer standing and status",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // =========================================================================
        // 2. Account Service Endpoints & DTOs
        // =========================================================================
        String svcAccount = "account-service";

        // GET /api/v1/accounts -> List<AccountView>
        addRule(svcAccount, "GET", "/api/v1/accounts", "id",
            DataSensitivityLevel.CONFIDENTIAL, "Bank account internal UUID identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "accountNumber",
            DataSensitivityLevel.CONFIDENTIAL, "Financial account number for routing/clearing",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "customerId",
            DataSensitivityLevel.CONFIDENTIAL, "Owner customer identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "currency",
            DataSensitivityLevel.CONFIDENTIAL, "Account denomination currency code (ISO-4217)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "balance",
            DataSensitivityLevel.CONFIDENTIAL, "Current financial ledger balance",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Account status (ACTIVE, FROZEN, CLOSED)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "openedAt",
            DataSensitivityLevel.CONFIDENTIAL, "Account opening timestamp",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts", "customer.*",
            DataSensitivityLevel.CONFIDENTIAL, "Nested customer profile summary on account view",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // GET /api/v1/accounts/{accountId} -> AccountView
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "id",
            DataSensitivityLevel.CONFIDENTIAL, "Bank account internal UUID identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "accountNumber",
            DataSensitivityLevel.CONFIDENTIAL, "Financial account number for routing/clearing",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "customerId",
            DataSensitivityLevel.CONFIDENTIAL, "Owner customer identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "currency",
            DataSensitivityLevel.CONFIDENTIAL, "Account denomination currency code (ISO-4217)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "balance",
            DataSensitivityLevel.CONFIDENTIAL, "Current financial ledger balance",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Account operational status",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "openedAt",
            DataSensitivityLevel.CONFIDENTIAL, "Account opening timestamp",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}", "customer.*",
            DataSensitivityLevel.CONFIDENTIAL, "Nested customer profile summary on account view",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // GET /api/v1/accounts/{accountId}/balance -> Balance
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}/balance", "accountId",
            DataSensitivityLevel.CONFIDENTIAL, "Bank account UUID identifier",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}/balance", "currency",
            DataSensitivityLevel.CONFIDENTIAL, "Account denomination currency code",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}/balance", "availableBalance",
            DataSensitivityLevel.CONFIDENTIAL, "Real-time available spendable financial balance",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcAccount, "GET", "/api/v1/accounts/{accountId}/balance", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Account operational status",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // POST /api/v1/accounts/{accountId}/debit -> DebitReceipt
        addRule(svcAccount, "POST", "/api/v1/accounts/{accountId}/debit", "reference",
            DataSensitivityLevel.CONFIDENTIAL, "Idempotent debit transaction reference",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "RECORD_DTO");
        addRule(svcAccount, "POST", "/api/v1/accounts/{accountId}/debit", "accountId",
            DataSensitivityLevel.CONFIDENTIAL, "Debited account identifier",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "RECORD_DTO");
        addRule(svcAccount, "POST", "/api/v1/accounts/{accountId}/debit", "amount",
            DataSensitivityLevel.CONFIDENTIAL, "Debited financial amount",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "RECORD_DTO");
        addRule(svcAccount, "POST", "/api/v1/accounts/{accountId}/debit", "currency",
            DataSensitivityLevel.CONFIDENTIAL, "Debited currency code",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "RECORD_DTO");
        addRule(svcAccount, "POST", "/api/v1/accounts/{accountId}/debit", "timestamp",
            DataSensitivityLevel.INTERNAL, "Debit ledger entry timestamp",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "RECORD_DTO");

        // =========================================================================
        // 3. Transaction Service Endpoints & DTOs
        // =========================================================================
        String svcTransaction = "transaction-service";

        // GET & POST /api/v1/beneficiaries -> BeneficiaryView
        String[] benRoutes = {"/api/v1/beneficiaries", "/api/v1/beneficiaries/{beneficiaryId}", "/api/v1/beneficiaries/{beneficiaryId}/verify"};
        for (String r : benRoutes) {
            String method = r.endsWith("/verify") ? "POST" : (r.equals("/api/v1/beneficiaries") ? "GET" : "GET");
            addRule(svcTransaction, method, r, "id",
                DataSensitivityLevel.CONFIDENTIAL, "Beneficiary entity UUID identifier",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "customerId",
                DataSensitivityLevel.CONFIDENTIAL, "Customer owner of beneficiary entry",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "name",
                DataSensitivityLevel.CONFIDENTIAL, "Recipient entity name",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "destinationAccountReference",
                DataSensitivityLevel.CONFIDENTIAL, "Destination financial routing account reference",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "currency",
                DataSensitivityLevel.CONFIDENTIAL, "Destination currency requirement",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "status",
                DataSensitivityLevel.CONFIDENTIAL, "Beneficiary verification state (PENDING, VERIFIED, REVOKED)",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "createdAt",
                DataSensitivityLevel.CONFIDENTIAL, "Beneficiary registration timestamp",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        }

        // POST /api/v1/beneficiaries (Create)
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "id",
            DataSensitivityLevel.CONFIDENTIAL, "Created beneficiary UUID",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "customerId",
            DataSensitivityLevel.CONFIDENTIAL, "Customer owner ID",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "name",
            DataSensitivityLevel.CONFIDENTIAL, "Beneficiary recipient name",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "destinationAccountReference",
            DataSensitivityLevel.CONFIDENTIAL, "Beneficiary destination account reference",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "currency",
            DataSensitivityLevel.CONFIDENTIAL, "Beneficiary currency requirement",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "status",
            DataSensitivityLevel.CONFIDENTIAL, "Initial beneficiary status (PENDING)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        addRule(svcTransaction, "POST", "/api/v1/beneficiaries", "createdAt",
            DataSensitivityLevel.CONFIDENTIAL, "Creation timestamp",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");

        // GET /api/v1/transactions & GET /api/v1/transactions/{transactionId} & POST /api/v1/transfers -> TransactionView
        String[] txRoutes = {"/api/v1/transactions", "/api/v1/transactions/{transactionId}", "/api/v1/transfers"};
        for (String r : txRoutes) {
            String method = r.equals("/api/v1/transfers") ? "POST" : "GET";
            addRule(svcTransaction, method, r, "id",
                DataSensitivityLevel.CONFIDENTIAL, "Transaction ledger UUID identifier",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "reference",
                DataSensitivityLevel.CONFIDENTIAL, "Idempotent financial transaction reference code",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "customerId",
                DataSensitivityLevel.CONFIDENTIAL, "Originating customer UUID identifier",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "sourceAccountId",
                DataSensitivityLevel.CONFIDENTIAL, "Debited funding account identifier",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "beneficiaryId",
                DataSensitivityLevel.CONFIDENTIAL, "Credited recipient beneficiary identifier",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "amount",
                DataSensitivityLevel.CONFIDENTIAL, "Financial funds transfer amount",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "currency",
                DataSensitivityLevel.CONFIDENTIAL, "Transaction funds currency (ISO-4217)",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "status",
                DataSensitivityLevel.CONFIDENTIAL, "Transaction lifecycle status (CREATED, PENDING, COMPLETED, FAILED)",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "createdAt",
                DataSensitivityLevel.CONFIDENTIAL, "Transaction initiation timestamp",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
            addRule(svcTransaction, method, r, "updatedAt",
                DataSensitivityLevel.CONFIDENTIAL, "Transaction completion/update timestamp",
                Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.OWNER_CUSTOMER, "RECORD_DTO");
        }

        // =========================================================================
        // 4. External Gateway & Authentication Secrets (RESTRICTED)
        // =========================================================================
        String svcAuth = "external-gateway";
        String tokenRoute = "/realms/aegis-dev/protocol/openid-connect/token";

        addRule(svcAuth, "POST", tokenRoute, "access_token",
            DataSensitivityLevel.RESTRICTED, "Bearer OAuth2/OIDC JWT conferring authenticated identity & roles",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.NONE, "POLICY_RULE");
        addRule(svcAuth, "POST", tokenRoute, "refresh_token",
            DataSensitivityLevel.RESTRICTED, "OAuth2 refresh credential capable of minting new tokens",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.NONE, "POLICY_RULE");
        addRule(svcAuth, "POST", tokenRoute, "id_token",
            DataSensitivityLevel.CONFIDENTIAL, "OIDC Identity token containing customer profile claims",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.NONE, "POLICY_RULE");
        addRule(svcAuth, "POST", tokenRoute, "token_type",
            DataSensitivityLevel.PUBLIC, "Standard token specification type (Bearer)",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.NONE, "POLICY_RULE");
        addRule(svcAuth, "POST", tokenRoute, "expires_in",
            DataSensitivityLevel.PUBLIC, "Token lifetime duration in seconds",
            Set.of("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.NONE, "POLICY_RULE");

        // Headers
        addRule(svcAuth, "*", "/*", "headers.authorization",
            DataSensitivityLevel.RESTRICTED, "HTTP Authorization bearer token header",
            Set.of(), ResourceOwnershipRequirement.NONE, "POLICY_RULE");
        addRule(svcAuth, "*", "/*", "headers.x-aegis-trust-token",
            DataSensitivityLevel.RESTRICTED, "Internal microservice HMAC trust token",
            Set.of("INTERNAL_SERVICE"), ResourceOwnershipRequirement.INTERNAL_SERVICE, "POLICY_RULE");

        // =========================================================================
        // 5. Operational Health & Actuator (PUBLIC & INTERNAL)
        // =========================================================================
        String svcOps = "security-gateway";
        addRule(svcOps, "GET", "/actuator/health", "status",
            DataSensitivityLevel.PUBLIC, "Overall service readiness status (UP, DOWN)",
            Set.of(), ResourceOwnershipRequirement.NONE, "OPENAPI_SPEC");
        addRule(svcOps, "GET", "/actuator/health", "components.*",
            DataSensitivityLevel.INTERNAL, "Detailed subsystem health diagnostics",
            Set.of("SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.ANALYST_ROLE, "OPENAPI_SPEC");
        addRule(svcOps, "GET", "/actuator/info", "build.*",
            DataSensitivityLevel.PUBLIC, "Application build version information",
            Set.of(), ResourceOwnershipRequirement.NONE, "OPENAPI_SPEC");

        // =========================================================================
        // 6. Security & SOC Endpoints (INTERNAL)
        // =========================================================================
        String[] secRoutes = {
            "/api/v1/security/overview", "/api/v1/security/events", "/api/v1/security/incidents",
            "/api/v1/security/reconciliation", "/api/v1/security/reconciliation/summary",
            "/api/v1/security/posture", "/api/v1/security/posture/summary",
            "/api/v1/security/discovery/endpoints", "/api/v1/security/specs", "/api/v1/security/policy-decisions"
        };
        for (String sr : secRoutes) {
            addRule(svcOps, "GET", sr, "totalElements",
                DataSensitivityLevel.INTERNAL, "Operational query pagination count",
                Set.of("SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.ANALYST_ROLE, "OPENAPI_SPEC");
            addRule(svcOps, "GET", sr, "content",
                DataSensitivityLevel.INTERNAL, "Security telemetry and analytics data",
                Set.of("SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.ANALYST_ROLE, "OPENAPI_SPEC");
            addRule(svcOps, "GET", sr, "summary",
                DataSensitivityLevel.INTERNAL, "Security posture and reconciliation metrics",
                Set.of("SECURITY_ANALYST", "SECURITY_ADMIN"), ResourceOwnershipRequirement.ANALYST_ROLE, "OPENAPI_SPEC");
        }
    }

    private void addRule(
            String serviceBoundary,
            String httpMethod,
            String routeTemplate,
            String fieldPath,
            DataSensitivityLevel level,
            String rationale,
            Set<String> approvedRoles,
            ResourceOwnershipRequirement ownership,
            String source) {

        registerRule(new FieldClassification(
            serviceBoundary,
            httpMethod,
            routeTemplate,
            fieldPath,
            level,
            rationale,
            approvedRoles,
            ownership,
            source,
            ClassificationConfidence.CONFIRMED,
            POLICY_VERSION,
            false
        ));
    }
}
