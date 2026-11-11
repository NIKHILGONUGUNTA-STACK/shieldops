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

/**
 * RULE-BULK-EXTRACT-01: Excessive Data Access and Bulk Extraction Detection.
 * Identifies automated data harvesting or systematic scraping of multiple confidential customer records
 * within a sliding time window.
 */
@Component
public class RuleBulkExtract01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleBulkExtract01.class);

    public static final String RULE_ID = "RULE-BULK-EXTRACT-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final SensitiveDataClassificationEngine classificationEngine;
    private final boolean enabled;
    private final int minDistinctResources;
    private final int cumulativeRecordThreshold;
    private final long singleResponseBytesThreshold;
    private final int windowSeconds;

    @Autowired
    public RuleBulkExtract01(
            DetectionStateStore stateStore,
            SensitiveDataClassificationEngine classificationEngine,
            @Value("${aegis.detection.rules.bulk-extract.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.bulk-extract.min-distinct-resources:3}") int minDistinctResources,
            @Value("${aegis.detection.rules.bulk-extract.cumulative-record-threshold:10}") int cumulativeRecordThreshold,
            @Value("${aegis.detection.rules.bulk-extract.single-response-bytes-threshold:20000}") long singleResponseBytesThreshold,
            @Value("${aegis.detection.rules.bulk-extract.window-seconds:120}") int windowSeconds) {
        this.stateStore = stateStore;
        this.classificationEngine = classificationEngine;
        this.enabled = enabled;
        this.minDistinctResources = minDistinctResources;
        this.cumulativeRecordThreshold = cumulativeRecordThreshold;
        this.singleResponseBytesThreshold = singleResponseBytesThreshold;
        this.windowSeconds = windowSeconds;
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
        if (event.statusCode() != 200) {
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
        String route = event.routeId() != null && !event.routeId().isBlank() ? event.routeId() : event.requestPath();
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

        // 5. Record access in state store
        stateStore.recordSensitiveAccess(
            customerId,
            event.id(),
            targetResourceId,
            route,
            event.recordCount(),
            event.responseSizeBytes(),
            eventTime
        );

        // 6. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<SensitiveAccessRecord> recentAccess = stateStore.getRecentSensitiveAccess(customerId, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctResources = new HashSet<>();
        int totalRecords = 0;
        long totalBytes = 0;

        for (SensitiveAccessRecord rec : recentAccess) {
            if (rec.eventId() != null) distinctEventIds.add(rec.eventId());
            if (rec.resourceId() != null && !rec.resourceId().isBlank()) distinctResources.add(rec.resourceId());
            totalRecords += rec.recordCount();
            totalBytes += rec.responseSizeBytes();
        }

        // 7. Check trigger thresholds
        boolean breachedDistinctResources = distinctResources.size() >= minDistinctResources;
        boolean breachedCumulativeRecords = totalRecords >= cumulativeRecordThreshold;
        boolean breachedSingleSize = event.responseSizeBytes() >= singleResponseBytesThreshold;

        if (!breachedDistinctResources && !breachedCumulativeRecords && !breachedSingleSize) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 8. Generate Detection Evidence
        UUID evidenceId = UUID.randomUUID();
        String breachReason = breachedDistinctResources
            ? String.format("%d distinct sensitive resources accessed (threshold: %d)", distinctResources.size(), minDistinctResources)
            : (breachedCumulativeRecords
                ? String.format("%d cumulative sensitive records extracted (threshold: %d)", totalRecords, cumulativeRecordThreshold)
                : String.format("Single response volume %d bytes exceeded threshold %d", event.responseSizeBytes(), singleResponseBytesThreshold));

        String triggerCondition = String.format(
            "Excessive data extraction by %s: %s within %ds window",
            customerId, breachReason, windowSeconds
        );

        String evidenceDetails = String.format(
            "Bulk Data Extraction: Entity=%s accessed %d distinct resources (%s) across %d events in %ds. Cumulative records=%d, cumulative bytes=%d. Reason: %s.",
            customerId, distinctResources.size(), distinctResources, distinctEventIds.size(), windowSeconds,
            totalRecords, totalBytes, breachReason
        );

        DetectionEvidence evidence = new DetectionEvidence(
            evidenceId,
            null,
            RULE_ID,
            RULE_VERSION,
            eventTime,
            0.88,
            "HIGH",
            triggerCondition,
            distinctEventIds.size(),
            windowSeconds,
            distinctResources.size(),
            evidenceDetails,
            new ArrayList<>(distinctEventIds),
            eventTime
        );

        String summary = String.format(
            "Excessive data extraction: %s accessed %d sensitive resources (%d records) within %ds",
            customerId, distinctResources.size(), totalRecords, windowSeconds
        );

        log.warn("RULE-BULK-EXTRACT-01 triggered for entity {}: {}", customerId, triggerCondition);

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

