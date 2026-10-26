package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SlidingWindowEvent;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * RULE-AUTH-01: Repeated authentication failures.
 * Detects brute force, credential stuffing, and unauthenticated attack probing across bounded time windows.
 */
@Component
public class RuleAuth01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleAuth01.class);

    public static final String RULE_ID = "RULE-AUTH-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int threshold;
    private final int windowSeconds;

    public RuleAuth01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.auth01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.auth01.threshold:5}") int threshold,
            @Value("${aegis.detection.rules.auth01.window-seconds:120}") int windowSeconds) {
        this.stateStore = stateStore;
        this.enabled = enabled;
        this.threshold = threshold;
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

        // 1. Must be HTTP 401 or explicit unauthenticated error code
        boolean isAuthFailure = event.statusCode() == 401 ||
            "UNAUTHENTICATED".equalsIgnoreCase(event.errorCode()) ||
            "UNAUTHENTICATED_ACCESS".equalsIgnoreCase(event.anomalyFlags());

        if (!isAuthFailure) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Exclude health and metrics endpoints
        String path = event.requestPath() != null ? event.requestPath() : "";
        if (path.startsWith("/actuator") || path.contains("/prometheus") || path.contains("/health")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Determine target entity (IP or authenticated subject if attempting bad re-auth)
        String targetEntityType;
        String targetEntityValue;

        if (event.authSubject() != null && !event.authSubject().isBlank() && !"anonymous".equalsIgnoreCase(event.authSubject())) {
            targetEntityType = "SUBJECT";
            targetEntityValue = event.authSubject().trim();
        } else {
            targetEntityType = "IP";
            targetEntityValue = event.sourceIp() != null && !event.sourceIp().isBlank()
                ? event.sourceIp().trim()
                : "127.0.0.1";
        }

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();
        String route = event.routeId() != null ? event.routeId() : path;

        // 4. Record failure in state store
        stateStore.recordAuthFailure(targetEntityValue, event.id(), route, eventTime);

        // 5. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<SlidingWindowEvent> attempts = stateStore.getRecentAuthFailures(targetEntityValue, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctRoutes = new HashSet<>();
        for (SlidingWindowEvent rec : attempts) {
            if (rec.eventId() != null) {
                distinctEventIds.add(rec.eventId());
            }
            if (rec.metadata() != null && !rec.metadata().isBlank()) {
                distinctRoutes.add(rec.metadata());
            }
        }

        int observedCount = distinctEventIds.size();

        // 6. Check threshold criteria
        if (observedCount >= threshold) {
            boolean isHighBurst = observedCount >= (threshold * 2);
            String severity = isHighBurst ? "HIGH" : "MEDIUM";
            double confidence = isHighBurst ? 0.95 : 0.85;

            String triggerCondition = String.format(
                "observed_auth_failures (%d) >= threshold (%d) across %d distinct routes",
                observedCount, threshold, distinctRoutes.size()
            );

            String evidenceDetails = String.format(
                "{\"target\":\"%s\",\"targetType\":\"%s\",\"observedFailures\":%d,\"distinctRoutes\":%s,\"windowSeconds\":%d}",
                targetEntityValue, targetEntityType, observedCount, distinctRoutes.toString(), windowSeconds
            );

            DetectionEvidence evidence = new DetectionEvidence(
                UUID.randomUUID(),
                null,
                RULE_ID,
                RULE_VERSION,
                Instant.now(),
                confidence,
                severity,
                triggerCondition,
                observedCount,
                windowSeconds,
                distinctRoutes.size(),
                evidenceDetails,
                new ArrayList<>(distinctEventIds),
                Instant.now()
            );

            String summary = String.format(
                "Repeated authentication failures detected from %s %s (%d failed attempts in %ds window)",
                targetEntityType, targetEntityValue, observedCount, windowSeconds
            );

            return RuleEvaluationResult.triggered(
                RULE_ID,
                RULE_VERSION,
                targetEntityType,
                targetEntityValue,
                evidence,
                summary
            );
        }

        return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
    }
}
