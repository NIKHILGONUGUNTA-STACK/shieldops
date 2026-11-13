package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.DataSensitivityLevel;
import com.aegis.gateway.classification.EndpointDataClassification;
import com.aegis.gateway.classification.SensitiveDataClassificationEngine;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SensitiveAccessRecord;
import com.aegis.gateway.detection.rules.DetectionRule;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * RULE-ADV-EXTRACT-01: Advanced Bulk Extraction & Multi-Vector Data Harvesting Detection.
 * Detects sophisticated, stealthy, and distributed data harvesting patterns across sensitive FinTech resources:
 * 1. Low-and-Slow Extraction: Spanning long observation windows (600s) below short-window rate limits.
 * 2. Distributed Extraction: Coordinated access across multiple sessions/tokens linked to one identity.
 * 3. Multi-Resource Extraction: Cross-domain harvesting across Customer, Account, and Transfer entities.
 * 4. Pagination Harvesting: Rapid progression of page/offset parameters scraping tabular records.
 * 5. Cumulative Volume Extraction: Excessive cumulative byte/record volume across sliding windows.
 *
 * Invariant: Never merges unrelated identities merely sharing a corporate NAT IP.
 * Invariant: Preserves baseline RULE-BULK-EXTRACT-01 intact.
 */
@Component
public class RuleAdvancedExtraction01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleAdvancedExtraction01.class);

    public static final String RULE_ID = "RULE-ADV-EXTRACT-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final SensitiveDataClassificationEngine classificationEngine;
    private final boolean enabled;

    // Configurable thresholds with justifications
    private final int shortWindowSeconds;              // 120s: Rapid harvesting window
    private final int longWindowSeconds;               // 600s: Low-and-slow extended window (10 min)
    private final int lowAndSlowResourceThreshold;     // >= 5 distinct resources over long window
    private final int distributedSessionThreshold;     // >= 2 distinct sessions/tokens per identity
    private final int multiResourceTypeThreshold;      // >= 2 distinct entity types (Customer + Account)
    private final int paginationPageThreshold;         // >= 3 distinct pages crawled rapidly
    private final int paginationRecordThreshold;       // >= 15 cumulative records scraped via pagination
    private final long cumulativeVolumeBytesThreshold; // >= 50,000 bytes cumulative sensitive volume

    @Autowired
    public RuleAdvancedExtraction01(
            DetectionStateStore stateStore,
            SensitiveDataClassificationEngine classificationEngine,
            @Value("${aegis.detection.rules.advanced-extraction.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.advanced-extraction.short-window-seconds:120}") int shortWindowSeconds,
            @Value("${aegis.detection.rules.advanced-extraction.long-window-seconds:600}") int longWindowSeconds,
            @Value("${aegis.detection.rules.advanced-extraction.low-and-slow-threshold:5}") int lowAndSlowResourceThreshold,
            @Value("${aegis.detection.rules.advanced-extraction.distributed-session-threshold:2}") int distributedSessionThreshold,
            @Value("${aegis.detection.rules.advanced-extraction.multi-resource-threshold:2}") int multiResourceTypeThreshold,
            @Value("${aegis.detection.rules.advanced-extraction.pagination-page-threshold:3}") int paginationPageThreshold,
            @Value("${aegis.detection.rules.advanced-extraction.pagination-record-threshold:15}") int paginationRecordThreshold,
            @Value("${aegis.detection.rules.advanced-extraction.cumulative-volume-bytes:50000}") long cumulativeVolumeBytesThreshold) {
        this.stateStore = stateStore;
        this.classificationEngine = classificationEngine;
        this.enabled = enabled;
        this.shortWindowSeconds = shortWindowSeconds;
        this.longWindowSeconds = longWindowSeconds;
        this.lowAndSlowResourceThreshold = lowAndSlowResourceThreshold;
        this.distributedSessionThreshold = distributedSessionThreshold;
        this.multiResourceTypeThreshold = multiResourceTypeThreshold;
        this.paginationPageThreshold = paginationPageThreshold;
        this.paginationRecordThreshold = paginationRecordThreshold;
        this.cumulativeVolumeBytesThreshold = cumulativeVolumeBytesThreshold;
    }

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getRuleVersion() {
        return RULE_VERSION;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public RuleEvaluationResult evaluate(ApiEvent event) {
        if (!enabled || event == null) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 1. Must be a successful response
        if (event.statusCode() != 200 && event.statusCode() != 201) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Caller must have an identified customer or subject
        String customerId = event.customerId();
        if (customerId == null || customerId.isBlank() || "anonymous".equalsIgnoreCase(customerId)) {
            customerId = event.authSubject();
        }
        if (customerId == null || customerId.isBlank() || "anonymous".equalsIgnoreCase(customerId)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Exclude privileged security analysts and internal services
        String roles = event.authRoles() != null ? event.authRoles().toUpperCase() : "";
        if (roles.contains("SECURITY_ANALYST") || roles.contains("SECURITY_ADMIN") || roles.contains("INTERNAL_SERVICE")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 4. Must target sensitive endpoint
        String method = event.httpMethod() != null ? event.httpMethod().toUpperCase() : "GET";
        String rawRoute = event.routeId() != null && !event.routeId().isBlank() ? event.routeId() : event.requestPath();
        String route = com.aegis.gateway.discovery.RouteNormalizer.normalize(rawRoute);
        EndpointDataClassification classification = classificationEngine.classifyEndpoint(method, route);

        if (classification == null ||
            (classification.highestSensitivityLevel() != DataSensitivityLevel.CONFIDENTIAL &&
             classification.highestSensitivityLevel() != DataSensitivityLevel.RESTRICTED)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        String targetResourceId = event.resourceId() != null && !event.resourceId().isBlank()
            ? event.resourceId().trim()
            : event.requestPath();

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();
        String resourceType = event.resourceType() != null && !event.resourceType().isBlank() ? event.resourceType() : "UNKNOWN";

        // 5. Record access in state store with full context
        stateStore.recordSensitiveAccess(
            customerId,
            event.id(),
            resourceType,
            targetResourceId,
            route,
            event.recordCount(),
            event.responseSizeBytes(),
            event.authSubject(),
            event.pageNumber(),
            classification.highestSensitivityLevel().name(),
            eventTime
        );

        // 6. Query sliding windows: both short window (120s) and long window (600s)
        Instant longWindowStart = eventTime.minusSeconds(longWindowSeconds);
        List<SensitiveAccessRecord> longRecords = stateStore.getRecentSensitiveAccess(customerId, longWindowStart);

        Instant shortWindowStart = eventTime.minusSeconds(shortWindowSeconds);
        List<SensitiveAccessRecord> shortRecords = longRecords.stream()
            .filter(r -> !r.timestamp().isBefore(shortWindowStart))
            .toList();

        // 7. Evaluate Detection Vectors

        // Vector A: Pagination-Based Harvesting
        Set<Integer> distinctPages = new HashSet<>();
        int paginationTotalRecords = 0;
        for (SensitiveAccessRecord r : shortRecords) {
            if (r.pageNumber() != null) {
                distinctPages.add(r.pageNumber());
                paginationTotalRecords += r.recordCount();
            }
        }
        boolean breachedPagination = distinctPages.size() >= paginationPageThreshold ||
            (distinctPages.size() >= 2 && paginationTotalRecords >= paginationRecordThreshold);

        // Vector B: Distributed Extraction Across Sessions
        Set<String> distinctSessions = new HashSet<>();
        Set<String> shortResources = new HashSet<>();
        for (SensitiveAccessRecord r : shortRecords) {
            if (r.authSubject() != null && !r.authSubject().isBlank()) {
                distinctSessions.add(r.authSubject());
            }
            if (r.resourceId() != null && !r.resourceId().isBlank()) {
                shortResources.add(r.resourceId());
            }
        }
        boolean breachedDistributed = distinctSessions.size() >= distributedSessionThreshold && shortResources.size() >= 3;

        // Vector C: Multi-Resource Extraction (Customer + Account + Transfer)
        Set<String> distinctResourceTypes = new HashSet<>();
        for (SensitiveAccessRecord r : shortRecords) {
            if (r.resourceType() != null && !r.resourceType().equalsIgnoreCase("UNKNOWN")) {
                distinctResourceTypes.add(r.resourceType());
            }
        }
        boolean breachedMultiResource = distinctResourceTypes.size() >= multiResourceTypeThreshold && shortResources.size() >= 3;

        // Vector D: Low-and-Slow Extraction (Extended Window 600s)
        Set<String> longResources = new HashSet<>();
        int longTotalRecords = 0;
        long longTotalBytes = 0;
        for (SensitiveAccessRecord r : longRecords) {
            if (r.resourceId() != null && !r.resourceId().isBlank()) {
                longResources.add(r.resourceId());
            }
            longTotalRecords += r.recordCount();
            longTotalBytes += r.responseSizeBytes();
        }
        // Low and slow applies when cumulative distinct resources over long window >= threshold,
        // but short window distinct count was kept moderate (< 3)
        boolean breachedLowAndSlow = longResources.size() >= lowAndSlowResourceThreshold && shortResources.size() < 3;

        // Vector E: Cumulative Response Volume Threshold
        boolean breachedVolume = longTotalBytes >= cumulativeVolumeBytesThreshold;

        // 8. Check if any advanced vector breached
        if (!breachedPagination && !breachedDistributed && !breachedMultiResource && !breachedLowAndSlow && !breachedVolume) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 9. Construct Explainable Forensic Finding
        String threatCategory;
        String breachReason;
        int activeWindow;
        int distinctResourceCount;
        double confidence;
        String severity = "HIGH";

        if (breachedDistributed) {
            threatCategory = "DISTRIBUTED_EXTRACTION";
            activeWindow = shortWindowSeconds;
            distinctResourceCount = shortResources.size();
            confidence = 0.94;
            severity = "CRITICAL";
            breachReason = String.format("Coordinated extraction across %d sessions targeting %d distinct resources in %ds",
                distinctSessions.size(), shortResources.size(), shortWindowSeconds);
        } else if (breachedPagination) {
            threatCategory = "PAGINATION_EXTRACTION";
            activeWindow = shortWindowSeconds;
            distinctResourceCount = shortResources.size();
            confidence = 0.92;
            breachReason = String.format("Automated pagination harvesting across %d distinct pages (%d cumulative records) in %ds",
                distinctPages.size(), paginationTotalRecords, shortWindowSeconds);
        } else if (breachedMultiResource) {
            threatCategory = "MULTI_RESOURCE_EXTRACTION";
            activeWindow = shortWindowSeconds;
            distinctResourceCount = shortResources.size();
            confidence = 0.91;
            breachReason = String.format("Cross-resource domain extraction spanning %d entity types (%s) across %d resources in %ds",
                distinctResourceTypes.size(), distinctResourceTypes, shortResources.size(), shortWindowSeconds);
        } else if (breachedLowAndSlow) {
            threatCategory = "LOW_AND_SLOW_EXTRACTION";
            activeWindow = longWindowSeconds;
            distinctResourceCount = longResources.size();
            confidence = 0.89;
            breachReason = String.format("Low-and-slow cumulative extraction across %d distinct resources (%d records) over extended %ds window",
                longResources.size(), longTotalRecords, longWindowSeconds);
        } else {
            threatCategory = "EXCESSIVE_DATA_EXTRACTION";
            activeWindow = longWindowSeconds;
            distinctResourceCount = longResources.size();
            confidence = 0.86;
            breachReason = String.format("Cumulative response volume reached %d bytes (threshold: %d bytes) across %ds window",
                longTotalBytes, cumulativeVolumeBytesThreshold, longWindowSeconds);
        }

        String triggerCondition = String.format(
            "Advanced Data Extraction [%s] by %s: %s",
            threatCategory, customerId, breachReason
        );

        List<UUID> contributingIds = (activeWindow == shortWindowSeconds ? shortRecords : longRecords).stream()
            .map(SensitiveAccessRecord::eventId)
            .filter(Objects::nonNull)
            .distinct()
            .toList();

        String evidenceDetails = String.format(
            "Advanced Extraction Analysis: Entity=%s, Category=%s. Window=%ds. " +
            "ContributingEvents=%d, DistinctResources=%d. " +
            "Metrics: [ShortResources=%d, LongResources=%d, DistinctPages=%s, DistinctSessions=%s, DistinctTypes=%s, TotalBytes=%d]. " +
            "BreachRationale: %s.",
            customerId, threatCategory, activeWindow,
            contributingIds.size(), distinctResourceCount,
            shortResources.size(), longResources.size(), distinctPages, distinctSessions, distinctResourceTypes, longTotalBytes,
            breachReason
        );

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            RULE_ID,
            RULE_VERSION,
            eventTime,
            confidence,
            severity,
            triggerCondition,
            contributingIds.size(),
            activeWindow,
            distinctResourceCount,
            evidenceDetails,
            contributingIds,
            eventTime
        );

        String summary = String.format(
            "%s: %s extracted %d sensitive resources (%s)",
            threatCategory, customerId, distinctResourceCount, breachReason
        );

        log.warn("RULE-ADV-EXTRACT-01 triggered for entity {}: {}", customerId, triggerCondition);

        return RuleEvaluationResult.triggered(
            RULE_ID,
            RULE_VERSION,
            "CUSTOMER",
            customerId,
            evidence,
            summary
        );
    }
}
