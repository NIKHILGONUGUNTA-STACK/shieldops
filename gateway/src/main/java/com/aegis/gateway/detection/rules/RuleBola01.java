package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

@Component
public class RuleBola01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleBola01.class);

    public static final String RULE_ID = "RULE-BOLA-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int threshold;
    private final int windowSeconds;
    private final int minDistinctResources;

    public RuleBola01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.bola01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.bola01.threshold:3}") int threshold,
            @Value("${aegis.detection.rules.bola01.window-seconds:300}") int windowSeconds,
            @Value("${aegis.detection.rules.bola01.min-distinct-resources:2}") int minDistinctResources) {
        this.stateStore = stateStore;
        this.enabled = enabled;
        this.threshold = threshold;
        this.windowSeconds = windowSeconds;
        this.minDistinctResources = minDistinctResources;
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
        if (!enabled) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 1. Must be a 403 Forbidden outcome
        if (event.statusCode() != 403) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Caller must have an authenticated customer identity
        String customerId = event.customerId();
        if (customerId == null || customerId.isBlank() || "anonymous".equalsIgnoreCase(customerId)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Must be trustworthy BOLA evidence, not a generic role or HMAC rejection
        if (!isTrustworthyBolaEvent(event)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        String targetResourceId = event.resourceId() != null && !event.resourceId().isBlank()
            ? event.resourceId().trim()
            : extractResourceIdFromPath(event.requestPath());

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();

        // 4. Record attempt in state store
        stateStore.recordBolaAttempt(customerId, event.id(), targetResourceId, eventTime);

        // 5. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<BolaAttemptRecord> attempts = stateStore.getRecentBolaAttempts(customerId, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctResources = new HashSet<>();

        for (BolaAttemptRecord rec : attempts) {
            if (rec.eventId() != null) {
                distinctEventIds.add(rec.eventId());
            }
            if (rec.resourceId() != null && !rec.resourceId().isBlank()) {
                distinctResources.add(rec.resourceId());
            }
        }

        int observedCount = distinctEventIds.size();
        List<UUID> eventIds = new ArrayList<>(distinctEventIds);

        // 6. Check threshold criteria
        // Primary BOLA pattern: >= threshold attempts and >= minDistinctResources distinct targeted entities
        boolean isHighConfidenceTrigger = observedCount >= threshold && distinctResources.size() >= minDistinctResources;
        // Secondary pattern: excessive repetitive attempts against single target (e.g. >= threshold + 2)
        boolean isSingleTargetRepeatedTrigger = observedCount >= (threshold + 2) && distinctResources.size() == 1;

        if (isHighConfidenceTrigger || isSingleTargetRepeatedTrigger) {
            String severity = isHighConfidenceTrigger ? "HIGH" : "MEDIUM";
            double confidence = isHighConfidenceTrigger ? 0.95 : 0.80;
            String triggerCondition = isHighConfidenceTrigger
                ? String.format("observed_attempts (%d) >= threshold (%d) AND distinct_resources (%d) >= %d",
                    observedCount, threshold, distinctResources.size(), minDistinctResources)
                : String.format("repeated_single_target_attempts (%d) >= %d", observedCount, threshold + 2);

            String evidenceDetails = String.format(
                "{\"customerId\":\"%s\",\"authSubject\":\"%s\",\"distinctResources\":%s,\"observedAttempts\":%d,\"windowSeconds\":%d}",
                customerId,
                event.authSubject() != null ? event.authSubject() : "",
                distinctResources.toString(),
                observedCount,
                windowSeconds
            );

            DetectionEvidence evidence = new DetectionEvidence(
                UUID.randomUUID(),
                null, // will be populated when attached to incident
                RULE_ID,
                RULE_VERSION,
                Instant.now(),
                confidence,
                severity,
                triggerCondition,
                observedCount,
                windowSeconds,
                distinctResources.size(),
                evidenceDetails,
                eventIds,
                Instant.now()
            );

            String summary = String.format(
                "Cross-customer BOLA probing detected for customer %s (%d unauthorized attempts across %d distinct resources in %ds window)",
                customerId, observedCount, distinctResources.size(), windowSeconds
            );

            return RuleEvaluationResult.triggered(
                RULE_ID,
                RULE_VERSION,
                "CUSTOMER",
                customerId,
                evidence,
                summary
            );
        }

        return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
    }

    private boolean isTrustworthyBolaEvent(ApiEvent event) {
        // Explicitly check for classified error code if available
        if ("BOLA_VIOLATION".equalsIgnoreCase(event.errorCode())) {
            return true;
        }

        // Exclude generic non-BOLA endpoints (e.g. security admin endpoints or actuator)
        String route = event.routeId() != null ? event.routeId() : "";
        String path = event.requestPath() != null ? event.requestPath() : "";

        if (path.contains("/security/") || path.contains("/actuator")) {
            return false;
        }

        // Check if route is a tenant-scoped resource endpoint
        boolean isTenantRoute = route.contains("/customers") || route.contains("/accounts") ||
                                path.contains("/customers") || path.contains("/accounts");

        if (!isTenantRoute) {
            return false;
        }

        // Check if resource ID is specified and distinct from caller customer ID
        String resourceId = event.resourceId() != null ? event.resourceId().trim() : extractResourceIdFromPath(path);
        String customerId = event.customerId() != null ? event.customerId().trim() : "";

        if (resourceId.isBlank() || "UNKNOWN".equalsIgnoreCase(resourceId)) {
            return false;
        }

        if (!customerId.isBlank()) {
            return !resourceId.equalsIgnoreCase(customerId);
        }

        return false;
    }

    private String extractResourceIdFromPath(String path) {
        if (path == null) return "UNKNOWN";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("/(customers|accounts)/([0-9a-fA-F-]+|ACCT-[a-zA-Z0-9_-]+)").matcher(path);
        if (m.find()) {
            return m.group(2);
        }
        return "UNKNOWN";
    }
}
