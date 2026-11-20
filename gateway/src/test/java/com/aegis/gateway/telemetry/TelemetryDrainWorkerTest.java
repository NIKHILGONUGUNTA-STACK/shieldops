package com.aegis.gateway.telemetry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.connection.stream.*;
import org.springframework.data.redis.core.StreamOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class TelemetryDrainWorkerTest {

    private StringRedisTemplate redisTemplate;
    private StreamOperations<String, Object, Object> streamOps;
    private ApiEventRepository repository;
    private TelemetryDrainWorker worker;

    private final String streamKey = "aegis:stream:api-events";

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        streamOps = mock(StreamOperations.class);
        when(redisTemplate.opsForStream()).thenReturn(streamOps);
        repository = mock(ApiEventRepository.class);

        worker = new TelemetryDrainWorker(
            redisTemplate,
            repository,
            streamKey,
            50
        );

        // By default, reading from offset "0" returns empty unless explicitly configured
        when(streamOps.read(
            eq(Consumer.from(TelemetryDrainWorker.DRAIN_GROUP, TelemetryDrainWorker.DRAIN_CONSUMER)),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.from("0")))
        )).thenReturn(Collections.emptyList());
    }

    @Test
    @DisplayName("Should successfully read stream records, save to repository, and acknowledge processed records")
    @SuppressWarnings("unchecked")
    void testDrainStreamSuccessfully() {
        RecordId recordId = RecordId.of("1700000000000-0");
        UUID eventId = UUID.randomUUID();
        Map<String, String> fields = new HashMap<>();
        fields.put("id", eventId.toString());
        fields.put("correlationId", "corr-drain-1");
        fields.put("timestamp", Instant.now().toString());
        fields.put("sourceIp", "127.0.0.1");
        fields.put("httpMethod", "GET");
        fields.put("requestPath", "/api/v1/customers");
        fields.put("statusCode", "200");
        fields.put("latencyMs", "15");
        fields.put("authSubject", "analyst");
        fields.put("authRoles", "ROLE_SECURITY_ANALYST");

        MapRecord<String, Object, Object> record = MapRecord.create(streamKey, (Map<Object, Object>) (Map<?, ?>) fields).withId(recordId);

        when(streamOps.read(
            eq(Consumer.from(TelemetryDrainWorker.DRAIN_GROUP, TelemetryDrainWorker.DRAIN_CONSUMER)),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(List.of(record));

        worker.drainStream();

        ArgumentCaptor<List<ApiEvent>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository, times(1)).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).id()).isEqualTo(eventId);
        assertThat(captor.getValue().get(0).correlationId()).isEqualTo("corr-drain-1");

        verify(streamOps, times(1)).acknowledge(eq(streamKey), eq(TelemetryDrainWorker.DRAIN_GROUP), eq(recordId));
    }

    @Test
    @DisplayName("Should recover unacknowledged pending messages from offset 0 on startup/cycle")
    @SuppressWarnings("unchecked")
    void testRecoverPendingMessagesFromPel() {
        RecordId recordId = RecordId.of("1699999999999-0");
        UUID eventId = UUID.randomUUID();
        Map<String, String> fields = new HashMap<>();
        fields.put("id", eventId.toString());
        fields.put("correlationId", "corr-pending-recovery");
        fields.put("timestamp", Instant.now().toString());
        fields.put("sourceIp", "10.0.0.5");
        fields.put("httpMethod", "POST");
        fields.put("requestPath", "/api/v1/transfers");
        fields.put("statusCode", "201");
        fields.put("latencyMs", "45");

        MapRecord<String, Object, Object> record = MapRecord.create(streamKey, (Map<Object, Object>) (Map<?, ?>) fields).withId(recordId);

        // When reading from offset "0"
        when(streamOps.read(
            eq(Consumer.from(TelemetryDrainWorker.DRAIN_GROUP, TelemetryDrainWorker.DRAIN_CONSUMER)),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.from("0")))
        )).thenReturn(List.of(record));

        worker.recoverPendingMessages();

        ArgumentCaptor<List<ApiEvent>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository, times(1)).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).id()).isEqualTo(eventId);

        verify(streamOps, times(1)).acknowledge(eq(streamKey), eq(TelemetryDrainWorker.DRAIN_GROUP), eq(recordId));
    }

    @Test
    @DisplayName("Should acknowledge and drop malformed/poison records to prevent stream and PEL freezes")
    @SuppressWarnings("unchecked")
    void testHandleMalformedPoisonRecord() {
        RecordId poisonId = RecordId.of("1700000000001-0");
        Map<String, String> badFields = new HashMap<>();
        badFields.put("id", "not-a-valid-uuid");
        badFields.put("timestamp", "invalid-date");

        MapRecord<String, Object, Object> poisonRecord = MapRecord.create(streamKey, (Map<Object, Object>) (Map<?, ?>) badFields).withId(poisonId);

        when(streamOps.read(
            eq(Consumer.from(TelemetryDrainWorker.DRAIN_GROUP, TelemetryDrainWorker.DRAIN_CONSUMER)),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(List.of(poisonRecord));

        worker.drainStream();

        // Repository should not receive invalid events
        verify(repository, never()).saveAll(any());

        // But poison record must still be acknowledged to prevent PEL freeze
        verify(streamOps, times(1)).acknowledge(eq(streamKey), eq(TelemetryDrainWorker.DRAIN_GROUP), eq(poisonId));
    }

    @Test
    @DisplayName("Should process mixed batch persisting valid events and acknowledging all records")
    @SuppressWarnings("unchecked")
    void testProcessMixedBatchWithPoisonPill() {
        RecordId validId = RecordId.of("1700000000002-0");
        RecordId poisonId = RecordId.of("1700000000002-1");

        UUID validEventId = UUID.randomUUID();
        Map<String, String> validFields = new HashMap<>();
        validFields.put("id", validEventId.toString());
        validFields.put("correlationId", "corr-valid");
        validFields.put("timestamp", Instant.now().toString());
        validFields.put("sourceIp", "127.0.0.1");
        validFields.put("httpMethod", "GET");
        validFields.put("requestPath", "/api/v1/accounts");
        validFields.put("statusCode", "200");

        Map<String, String> poisonFields = new HashMap<>();
        poisonFields.put("id", "invalid-uuid");

        MapRecord<String, Object, Object> validRecord = MapRecord.create(streamKey, (Map<Object, Object>) (Map<?, ?>) validFields).withId(validId);
        MapRecord<String, Object, Object> poisonRecord = MapRecord.create(streamKey, (Map<Object, Object>) (Map<?, ?>) poisonFields).withId(poisonId);

        when(streamOps.read(
            eq(Consumer.from(TelemetryDrainWorker.DRAIN_GROUP, TelemetryDrainWorker.DRAIN_CONSUMER)),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(List.of(validRecord, poisonRecord));

        worker.drainStream();

        ArgumentCaptor<List<ApiEvent>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository, times(1)).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).id()).isEqualTo(validEventId);

        // Both valid and poison record should be acknowledged
        verify(streamOps, times(1)).acknowledge(eq(streamKey), eq(TelemetryDrainWorker.DRAIN_GROUP), eq(validId));
        verify(streamOps, times(1)).acknowledge(eq(streamKey), eq(TelemetryDrainWorker.DRAIN_GROUP), eq(poisonId));
    }
}
