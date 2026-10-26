package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DataVolumeRecord;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.SlidingWindowEvent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * State store interface for sliding-window threat detection.
 * Provides bounded, TTL-managed, and event-deduplicating storage backed by Redis with local memory fallback.
 */
public interface DetectionStateStore {
    // RULE-BOLA-01
    void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp);
    List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since);
    void clear(String customerId);

    // RULE-AUTH-01: Authentication failures (keyed by sourceIp or authSubject)
    void recordAuthFailure(String entityKey, UUID eventId, String route, Instant timestamp);
    List<SlidingWindowEvent> getRecentAuthFailures(String entityKey, Instant since);

    // RULE-DATA-01: Data access metrics (keyed by customerId)
    void recordDataAccess(String customerId, UUID eventId, int recordCount, long responseSizeBytes, Instant timestamp);
    List<DataVolumeRecord> getRecentDataAccess(String customerId, Instant since);

    // RULE-RATE-01: API request bursts (keyed by customerId or sourceIp)
    void recordRequest(String entityKey, UUID eventId, String route, Instant timestamp);
    List<SlidingWindowEvent> getRecentRequests(String entityKey, Instant since);

    // RULE-PROBE-01: Probing & validation errors (keyed by customerId or sourceIp)
    void recordProbeAttempt(String entityKey, UUID eventId, String path, String payloadHash, int statusCode, Instant timestamp);
    List<ProbeRecord> getRecentProbeAttempts(String entityKey, Instant since);

    // RULE-INJ-01: Injection indicators (keyed by customerId or sourceIp)
    void recordInjectionAttempt(String entityKey, UUID eventId, String patternType, Instant timestamp);
    List<SlidingWindowEvent> getRecentInjectionAttempts(String entityKey, Instant since);

    // Generic key cleanup
    void clearKey(String prefix, String entityKey);
}
