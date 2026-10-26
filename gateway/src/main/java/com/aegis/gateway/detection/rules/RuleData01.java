package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.DataVolumeRecord;
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

/**
 * RULE-DATA-01: Potential excessive data access.
 * Detects bulk data scraping, anomalous record harvesting, or abnormal exfiltration volumes
 * based on defensible response byte size and record count metrics.
 */
@Component
public class RuleData01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleData01.class);

    public static final String RULE_ID = "RULE-DATA-01";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final long singleResponseBytesThreshold;
    private final int singleRecordThreshold;
    private final long cumulativeBytesThreshold;
    private final int cumulativeRecordThreshold;
    private final int windowSeconds;

    public RuleData01(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.data01.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.data01.single-response-bytes-threshold:25000}") long singleResponseBytesThreshold,
            @Value("${aegis.detection.rules.data01.single-record-threshold:10}") int singleRecordThreshold,
            @Value("${aegis.detection.rules.data01.cumulative-bytes-threshold:3000}") long cumulativeBytesThreshold,
            @Value("${aegis.detection.rules.data01.cumulative-record-threshold:6}") int cumulativeRecordThreshold,
            @Value("${aegis.detection.rules.data01.window-seconds:120}") int windowSeconds) {
        this.stateStore = stateStore;
        this.enabled = enabled;
        this.singleResponseBytesThreshold = singleResponseBytesThreshold;
        this.singleRecordThreshold = singleRecordThreshold;
        this.cumulativeBytesThreshold = cumulativeBytesThreshold;
        this.cumulativeRecordThreshold = cumulativeRecordThreshold;
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

        // 1. Must be a successful response (HTTP 200)
        if (event.statusCode() != 200) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Caller must have authenticated customer identity
        String customerId = event.customerId();
        if (customerId == null || customerId.isBlank() || "anonymous".equalsIgnoreCase(customerId)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Exclude admin security event queries and actuator probes
        String path = event.requestPath() != null ? event.requestPath() : "";
        if (path.startsWith("/actuator") || path.contains("/security/") || path.contains("/prometheus")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 4. Must involve actual response data
        long eventBytes = event.responseSizeBytes();
        int eventRecords = event.recordCount();
        if (eventBytes <= 0 && eventRecords <= 0) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();

        // 5. Record event in state store
        stateStore.recordDataAccess(customerId, event.id(), eventRecords, eventBytes, eventTime);

        // 6. Query sliding window
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<DataVolumeRecord> records = stateStore.getRecentDataAccess(customerId, windowStart);

        // Deduplicate by distinct event ID
        Map<UUID, DataVolumeRecord> distinctEvents = new LinkedHashMap<>();
        for (DataVolumeRecord rec : records) {
            if (rec.eventId() != null) {
                distinctEvents.put(rec.eventId(), rec);
            }
        }

        int cumulativeRecords = 0;
        long cumulativeBytes = 0;
        for (DataVolumeRecord rec : distinctEvents.values()) {
            cumulativeRecords += rec.recordCount();
            cumulativeBytes += rec.responseSizeBytes();
        }

        // 7. Evaluate trigger conditions
        boolean isSingleBurst = eventBytes >= singleResponseBytesThreshold || eventRecords >= singleRecordThreshold;
        boolean isCumulativeBurst = cumulativeBytes >= cumulativeBytesThreshold || cumulativeRecords >= cumulativeRecordThreshold;

        if (isSingleBurst || isCumulativeBurst) {
            boolean isMassiveExfiltration = cumulativeBytes >= (cumulativeBytesThreshold * 2) ||
                                            cumulativeRecords >= (cumulativeRecordThreshold * 2);
            String severity = isMassiveExfiltration ? "HIGH" : "MEDIUM";
            double confidence = isMassiveExfiltration ? 0.92 : 0.85;

            String triggerCondition;
            if (isSingleBurst && isCumulativeBurst) {
                triggerCondition = String.format(
                    "single_response (%d bytes, %d records) AND cumulative_window (%d bytes, %d records across %d events) exceeded thresholds",
                    eventBytes, eventRecords, cumulativeBytes, cumulativeRecords, distinctEvents.size()
                );
            } else if (isSingleBurst) {
                triggerCondition = String.format(
                    "single_response (%d bytes >= %d OR %d records >= %d)",
                    eventBytes, singleResponseBytesThreshold, eventRecords, singleRecordThreshold
                );
            } else {
                triggerCondition = String.format(
                    "cumulative_volume (%d bytes >= %d OR %d records >= %d across %d events in %ds window)",
                    cumulativeBytes, cumulativeBytesThreshold, cumulativeRecords, cumulativeRecordThreshold,
                    distinctEvents.size(), windowSeconds
                );
            }

            String evidenceDetails = String.format(
                "{\"customerId\":\"%s\",\"cumulativeRecords\":%d,\"cumulativeBytes\":%d,\"distinctEvents\":%d,\"windowSeconds\":%d}",
                customerId, cumulativeRecords, cumulativeBytes, distinctEvents.size(), windowSeconds
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
                distinctEvents.size(),
                windowSeconds,
                distinctEvents.size(),
                evidenceDetails,
                new ArrayList<>(distinctEvents.keySet()),
                Instant.now()
            );

            String summary = String.format(
                "Potential excessive data access detected for customer %s (%d records, %d bytes across %d events in %ds window)",
                customerId, cumulativeRecords, cumulativeBytes, distinctEvents.size(), windowSeconds
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
}
