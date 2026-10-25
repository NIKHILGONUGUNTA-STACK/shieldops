package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface DetectionStateStore {
    void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp);
    List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since);
    void clear(String customerId);
}
