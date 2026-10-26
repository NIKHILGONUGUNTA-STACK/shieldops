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
import java.util.regex.Pattern;

/**
 * RULE-INJ-01: Carefully scoped injection indicators.
 * Detects SQL injection, directory traversal, command injection, and script payload injection
 * in request paths, resource parameters, or query indicators, while avoiding false positives on benign names or UUIDs.
 */
@Component
public class RuleInj01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleInj01.class);

    public static final String RULE_ID = "RULE-INJ-01";
    public static final String RULE_VERSION = "1.0.0";

    // Defensible, tightly scoped injection regex patterns
    private static final Pattern SQLI_PATTERN = Pattern.compile(
        "(?i)(\\b(UNION(\\s+ALL)?\\s+SELECT|SELECT\\s+.+\\s+FROM|INSERT\\s+INTO|DROP\\s+(TABLE|DATABASE)|WAITFOR\\s+DELAY|SLEEP\\(\\d+\\))\\b|'(\\s+|%20)+OR(\\s+|%20)+('1'='1|1=1)|--\\s*$)"
    );

    private static final Pattern TRAVERSAL_PATTERN = Pattern.compile(
        "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e(%2f|%5c|/|\\\\))"
    );

    private static final Pattern CMD_INJ_PATTERN = Pattern.compile(
        "(?i)(;|\\|)\\s*(cat|ls|id|whoami|sh|bash)\\b|\\$\\((whoami|id)\\)|`whoami`|`id`"
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)<\\s*script\\b|javascript\\s*:|onload\\s*=|onerror\\s*="
    );

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int threshold;
    private final int windowSeconds;

    public RuleInj01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.inj01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.inj01.threshold:1}") int threshold,
            @Value("${aegis.detection.rules.inj01.window-seconds:180}") int windowSeconds) {
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
        if (path.startsWith("/actuator") || path.contains("/prometheus")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Identify matched injection pattern
        String patternType = matchInjectionPattern(event);
        if (patternType == null) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Determine target identity
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

        // 4. Record injection event in state store
        stateStore.recordInjectionAttempt(targetEntityValue, event.id(), patternType, eventTime);

        // 5. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<SlidingWindowEvent> attempts = stateStore.getRecentInjectionAttempts(targetEntityValue, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctPatternTypes = new HashSet<>();

        for (SlidingWindowEvent rec : attempts) {
            if (rec.eventId() != null) {
                distinctEventIds.add(rec.eventId());
            }
            if (rec.metadata() != null && !rec.metadata().isBlank()) {
                distinctPatternTypes.add(rec.metadata());
            }
        }

        int observedCount = distinctEventIds.size();

        // 6. Evaluate threshold
        if (observedCount >= threshold) {
            boolean isCritical = observedCount >= 3 || distinctPatternTypes.size() >= 2;
            String severity = isCritical ? "CRITICAL" : "HIGH";
            double confidence = isCritical ? 0.95 : 0.90;

            String triggerCondition = String.format(
                "injection_indicators (%d) >= threshold (%d) matching %s patterns",
                observedCount, threshold, distinctPatternTypes.toString()
            );

            String evidenceDetails = String.format(
                "{\"target\":\"%s\",\"targetType\":\"%s\",\"observedAttempts\":%d,\"patternTypes\":%s,\"windowSeconds\":%d}",
                targetEntityValue, targetEntityType, observedCount, distinctPatternTypes.toString(), windowSeconds
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
                distinctPatternTypes.size(),
                evidenceDetails,
                new ArrayList<>(distinctEventIds),
                Instant.now()
            );

            String summary = String.format(
                "Injection indicators detected for %s %s (patterns: %s, %d attempts in %ds window)",
                targetEntityType, targetEntityValue, distinctPatternTypes.toString(), observedCount, windowSeconds
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

    private String matchInjectionPattern(ApiEvent event) {
        // Check anomaly flags or error codes flagged by TelemetryFilter
        if ("INJECTION_INDICATOR".equalsIgnoreCase(event.anomalyFlags()) ||
            "INJECTION_DETECTED".equalsIgnoreCase(event.errorCode())) {
            return "INDICATOR_FLAG";
        }

        String path = event.requestPath() != null ? event.requestPath() : "";
        String decodedPath = path;
        try {
            decodedPath = java.net.URLDecoder.decode(path, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            decodedPath = path;
        }
        String resourceId = event.resourceId() != null ? event.resourceId() : "";
        String combined = decodedPath + " " + path + " " + resourceId;

        if (SQLI_PATTERN.matcher(combined).find()) {
            return "SQL_INJECTION";
        }
        if (TRAVERSAL_PATTERN.matcher(combined).find()) {
            return "PATH_TRAVERSAL";
        }
        if (CMD_INJ_PATTERN.matcher(combined).find()) {
            return "COMMAND_INJECTION";
        }
        if (XSS_PATTERN.matcher(combined).find()) {
            return "CROSS_SITE_SCRIPTING";
        }

        return null;
    }
}
