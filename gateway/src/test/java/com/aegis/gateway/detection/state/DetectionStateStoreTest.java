package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DataVolumeRecord;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.SlidingWindowEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class DetectionStateStoreTest {

    private StringRedisTemplate redisTemplate;
    private RedisDetectionStateStore stateStore;

    @BeforeEach
    void setUp() {
        redisTemplate = Mockito.mock(StringRedisTemplate.class);
        // Simulate Redis outage so all operations fall back to the resilient in-memory fallback
        when(redisTemplate.opsForZSet()).thenThrow(new RuntimeException("Redis connection refused (outage simulation)"));
        stateStore = new RedisDetectionStateStore(redisTemplate);
    }

    @Test
    @DisplayName("Should fall back to in-memory store and retrieve BOLA attempts during Redis outage")
    void testBolaFallbackDuringRedisOutage() {
        String customerId = "cust-fallback-01";
        UUID eventId1 = UUID.randomUUID();
        UUID eventId2 = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordBolaAttempt(customerId, eventId1, "res-1", now.minusSeconds(10));
        stateStore.recordBolaAttempt(customerId, eventId2, "res-2", now);

        List<BolaAttemptRecord> attempts = stateStore.getRecentBolaAttempts(customerId, now.minusSeconds(30));
        assertThat(attempts).hasSize(2);
        assertThat(attempts.stream().map(BolaAttemptRecord::eventId)).containsExactlyInAnyOrder(eventId1, eventId2);

        // Prune older than since
        List<BolaAttemptRecord> pruned = stateStore.getRecentBolaAttempts(customerId, now.minusSeconds(5));
        assertThat(pruned).hasSize(1);
        assertThat(pruned.get(0).eventId()).isEqualTo(eventId2);
    }

    @Test
    @DisplayName("Should fall back to in-memory store and track Auth failures during Redis outage")
    void testAuthFallbackDuringRedisOutage() {
        String ip = "192.168.1.99";
        UUID evId = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordAuthFailure(ip, evId, "/api/v1/customers", now);
        List<SlidingWindowEvent> records = stateStore.getRecentAuthFailures(ip, now.minusSeconds(60));

        assertThat(records).hasSize(1);
        assertThat(records.get(0).eventId()).isEqualTo(evId);
        assertThat(records.get(0).metadata()).isEqualTo("/api/v1/customers");
    }

    @Test
    @DisplayName("Should fall back to in-memory store and track Data access during Redis outage")
    void testDataFallbackDuringRedisOutage() {
        String customerId = "cust-data-fallback";
        UUID evId = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordDataAccess(customerId, evId, 15, 25000L, now);
        List<DataVolumeRecord> records = stateStore.getRecentDataAccess(customerId, now.minusSeconds(60));

        assertThat(records).hasSize(1);
        assertThat(records.get(0).recordCount()).isEqualTo(15);
        assertThat(records.get(0).responseSizeBytes()).isEqualTo(25000L);
    }

    @Test
    @DisplayName("Should fall back to in-memory store and track Probe attempts during Redis outage")
    void testProbeFallbackDuringRedisOutage() {
        String customerId = "cust-probe-fallback";
        UUID evId = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordProbeAttempt(customerId, evId, "/api/v1/invalid", "hash123", 404, now);
        List<ProbeRecord> records = stateStore.getRecentProbeAttempts(customerId, now.minusSeconds(60));

        assertThat(records).hasSize(1);
        assertThat(records.get(0).path()).isEqualTo("/api/v1/invalid");
        assertThat(records.get(0).statusCode()).isEqualTo(404);
    }

    @Test
    @DisplayName("Should fall back to in-memory store and track Injection attempts during Redis outage")
    void testInjectionFallbackDuringRedisOutage() {
        String customerId = "cust-inj-fallback";
        UUID evId = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordInjectionAttempt(customerId, evId, "SQL_INJECTION", now);
        List<SlidingWindowEvent> records = stateStore.getRecentInjectionAttempts(customerId, now.minusSeconds(60));

        assertThat(records).hasSize(1);
        assertThat(records.get(0).metadata()).isEqualTo("SQL_INJECTION");
    }

    @Test
    @DisplayName("Should clear keys from in-memory fallback cleanly")
    void testClearKey() {
        String customerId = "cust-clear";
        UUID evId = UUID.randomUUID();
        Instant now = Instant.now();

        stateStore.recordBolaAttempt(customerId, evId, "res-1", now);
        assertThat(stateStore.getRecentBolaAttempts(customerId, now.minusSeconds(10))).hasSize(1);

        stateStore.clear(customerId);
        assertThat(stateStore.getRecentBolaAttempts(customerId, now.minusSeconds(10))).isEmpty();
    }
}
