package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DataVolumeRecord;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.SlidingWindowEvent;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory test implementation of DetectionStateStore for fast, deterministic unit testing.
 */
public class InMemoryDetectionStateStore implements DetectionStateStore {
    private final Map<String, List<BolaAttemptRecord>> bolaStore = new ConcurrentHashMap<>();
    private final Map<String, List<SlidingWindowEvent>> authStore = new ConcurrentHashMap<>();
    private final Map<String, List<DataVolumeRecord>> dataStore = new ConcurrentHashMap<>();
    private final Map<String, List<SlidingWindowEvent>> rateStore = new ConcurrentHashMap<>();
    private final Map<String, List<ProbeRecord>> probeStore = new ConcurrentHashMap<>();
    private final Map<String, List<SlidingWindowEvent>> injStore = new ConcurrentHashMap<>();

    @Override
    public void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp) {
        bolaStore.computeIfAbsent(customerId.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new BolaAttemptRecord(eventId, resourceId, timestamp));
    }

    @Override
    public List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since) {
        List<BolaAttemptRecord> records = bolaStore.getOrDefault(customerId.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void clear(String customerId) {
        bolaStore.remove(customerId.trim());
    }

    @Override
    public void recordAuthFailure(String entityKey, UUID eventId, String route, Instant timestamp) {
        authStore.computeIfAbsent(entityKey.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new SlidingWindowEvent(eventId, route, timestamp));
    }

    @Override
    public List<SlidingWindowEvent> getRecentAuthFailures(String entityKey, Instant since) {
        List<SlidingWindowEvent> records = authStore.getOrDefault(entityKey.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void recordDataAccess(String customerId, UUID eventId, int recordCount, long responseSizeBytes, Instant timestamp) {
        dataStore.computeIfAbsent(customerId.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new DataVolumeRecord(eventId, recordCount, responseSizeBytes, timestamp));
    }

    @Override
    public List<DataVolumeRecord> getRecentDataAccess(String customerId, Instant since) {
        List<DataVolumeRecord> records = dataStore.getOrDefault(customerId.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void recordRequest(String entityKey, UUID eventId, String route, Instant timestamp) {
        rateStore.computeIfAbsent(entityKey.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new SlidingWindowEvent(eventId, route, timestamp));
    }

    @Override
    public List<SlidingWindowEvent> getRecentRequests(String entityKey, Instant since) {
        List<SlidingWindowEvent> records = rateStore.getOrDefault(entityKey.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void recordProbeAttempt(String entityKey, UUID eventId, String path, String payloadHash, int statusCode, Instant timestamp) {
        probeStore.computeIfAbsent(entityKey.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new ProbeRecord(eventId, path, payloadHash, statusCode, timestamp));
    }

    @Override
    public List<ProbeRecord> getRecentProbeAttempts(String entityKey, Instant since) {
        List<ProbeRecord> records = probeStore.getOrDefault(entityKey.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void recordInjectionAttempt(String entityKey, UUID eventId, String patternType, Instant timestamp) {
        injStore.computeIfAbsent(entityKey.trim(), k -> new CopyOnWriteArrayList<>())
            .add(new SlidingWindowEvent(eventId, patternType, timestamp));
    }

    @Override
    public List<SlidingWindowEvent> getRecentInjectionAttempts(String entityKey, Instant since) {
        List<SlidingWindowEvent> records = injStore.getOrDefault(entityKey.trim(), Collections.emptyList());
        return records.stream().filter(r -> !r.timestamp().isBefore(since)).toList();
    }

    @Override
    public void clearKey(String prefix, String entityKey) {
        String trimmed = entityKey.trim();
        if (prefix.contains("bola")) bolaStore.remove(trimmed);
        else if (prefix.contains("auth")) authStore.remove(trimmed);
        else if (prefix.contains("data")) dataStore.remove(trimmed);
        else if (prefix.contains("rate")) rateStore.remove(trimmed);
        else if (prefix.contains("probe")) probeStore.remove(trimmed);
        else if (prefix.contains("inj")) injStore.remove(trimmed);
    }
}
