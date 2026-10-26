package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * RULE-PROBE-01: Suspicious probing and repeated validation failures.
 * Detects unmapped route exploration (404), schema/parameter fuzzing (400/422),
 * and separates malicious multi-target exploration from benign identical client retry loops.
 */
@Component
public class RuleProbe01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleProbe01.class);

    public static final String RULE_ID = "RULE-PROBE-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int threshold;
    private final int windowSeconds;

    public RuleProbe01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.probe01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.probe01.threshold:4}") int threshold,
            @Value("${aegis.detection.rules.probe01.window-seconds:180}") int windowSeconds) {
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

        // 1. Must be HTTP 400 Bad Request, 404 Not Found, or 422 Unprocessable Entity
        int status = event.statusCode();
        boolean isProbeStatus = status == 400 || status == 404 || status == 422 ||
            "VALIDATION_ERROR".equalsIgnoreCase(event.errorCode()) ||
            "NOT_FOUND".equalsIgnoreCase(event.errorCode());

        if (!isProbeStatus) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Exclude health and static asset paths
        String path = event.requestPath() != null ? event.requestPath() : "";
        if (path.startsWith("/actuator") || path.contains("/favicon.ico") || path.contains("/prometheus")) {
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
        String payloadHash = event.payloadHash() != null ? event.payloadHash() : "NONE";

        // 4. Record probe attempt in state store
        stateStore.recordProbeAttempt(targetEntityValue, event.id(), path, payloadHash, status, eventTime);

        // 5. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<ProbeRecord> attempts = stateStore.getRecentProbeAttempts(targetEntityValue, windowStart);

        Set<UUID> distinctEventIds = new LinkedHashSet<>();
        Set<String> distinctPaths = new HashSet<>();
        Set<String> distinctPayloadHashes = new HashSet<>();

        for (ProbeRecord rec : attempts) {
            if (rec.eventId() != null) {
                distinctEventIds.add(rec.eventId());
            }
            if (rec.path() != null && !rec.path().isBlank()) {
                distinctPaths.add(rec.path());
            }
            if (rec.payloadHash() != null && !"NONE".equalsIgnoreCase(rec.payloadHash())) {
                distinctPayloadHashes.add(rec.payloadHash());
            }
        }

        int observedCount = distinctEventIds.size();

        // 6. Benign Retry vs Malicious Probing Mitigation:
        // If all failures share the identical path and identical payload hash, it indicates a benign client retry loop.
        // In that case, do not flag unless it significantly exceeds standard threshold (e.g. >= threshold + 3).
        boolean isIdenticalRetryLoop = distinctPaths.size() == 1 && distinctPayloadHashes.size() <= 1;
        int effectiveThreshold = isIdenticalRetryLoop ? (threshold + 3) : threshold;

        if (observedCount >= effectiveThreshold) {
            boolean isHighProbing = distinctPaths.size() >= 3 || observedCount >= (threshold * 2);
            String severity = isHighProbing ? "HIGH" : "MEDIUM";
            double confidence = isHighProbing ? 0.90 : 0.85;

            String triggerCondition = String.format(
                "observed_probing_failures (%d) >= threshold (%d) across %d distinct paths (payload variants: %d)",
                observedCount, effectiveThreshold, distinctPaths.size(), Math.max(1, distinctPayloadHashes.size())
            );

            String evidenceDetails = String.format(
                "{\"target\":\"%s\",\"targetType\":\"%s\",\"observedFailures\":%d,\"distinctPaths\":%s,\"payloadVariants\":%d,\"windowSeconds\":%d}",
                targetEntityValue, targetEntityType, observedCount, distinctPaths.toString(),
                Math.max(1, distinctPayloadHashes.size()), windowSeconds
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
                distinctPaths.size(),
                evidenceDetails,
                new ArrayList<>(distinctEventIds),
                Instant.now()
            );

            String summary = String.format(
                "Suspicious probing and validation failures detected for %s %s (%d failures across %d distinct paths in %ds window)",
                targetEntityType, targetEntityValue, observedCount, distinctPaths.size(), windowSeconds
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
