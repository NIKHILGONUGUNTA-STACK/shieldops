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
 * RULE-RATE-01: Excessive request activity.
 * Detects automated API bursts, brute-force scraping, or unthrottled flooding.
 */
@Component
public class RuleRate01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleRate01.class);

    public static final String RULE_ID = "RULE-RATE-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int threshold;
    private final int windowSeconds;

    public RuleRate01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.rate01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.rate01.threshold:20}") int threshold,
            @Value("${aegis.detection.rules.rate01.window-seconds:60}") int windowSeconds) {
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

        // 1. Exclude actuator and monitoring routes
        String path = event.requestPath() != null ? event.requestPath() : "";
        if (path.startsWith("/actuator") || path.contains("/prometheus") || path.contains("/health")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Identify target entity (authenticated customer takes precedence over IP)
        String targetEntityType;
        String targetEntityValue;

        if (event.customerId() != null && !event.customerId().isBlank() && !"anonymous".equalsIgnoreCase(event.customerId())) {
            targetEntityType = "CUSTOMER";
            targetEntityValue = event.customerId().trim();
        } else {
            targetEntityType = "IP";
            targetEntityValue = event.sourceIp() != null && !event.sourceIp().isBlank()
                ? event.sourceIp().trim()
                : "127.0.0.1";
        }

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();
        String route = event.routeId() != null ? event.routeId() : path;

        // 3. Record event in sliding window
        stateStore.recordRequest(targetEntityValue, event.id(), route, eventTime);

        // 4. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<SlidingWindowEvent> requests = stateStore.getRecentRequests(targetEntityValue, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctRoutes = new HashSet<>();
        for (SlidingWindowEvent rec : requests) {
            if (rec.eventId() != null) {
                distinctEventIds.add(rec.eventId());
            }
            if (rec.metadata() != null && !rec.metadata().isBlank()) {
                distinctRoutes.add(rec.metadata());
            }
        }

        int observedCount = distinctEventIds.size();

        // 5. Evaluate threshold
        if (observedCount >= threshold) {
            boolean isExtremeBurst = observedCount >= (threshold * 2);
            String severity = isExtremeBurst ? "HIGH" : "MEDIUM";
            double confidence = isExtremeBurst ? 0.90 : 0.80;

            String triggerCondition = String.format(
                "observed_requests (%d) >= threshold (%d) across %d distinct routes in %ds window",
                observedCount, threshold, distinctRoutes.size(), windowSeconds
            );

            String evidenceDetails = String.format(
                "{\"target\":\"%s\",\"targetType\":\"%s\",\"observedRequests\":%d,\"distinctRoutes\":%s,\"windowSeconds\":%d}",
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
                "Excessive request activity detected for %s %s (%d requests in %ds window)",
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
