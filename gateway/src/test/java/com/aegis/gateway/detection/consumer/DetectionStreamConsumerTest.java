package com.aegis.gateway.detection.consumer;

import com.aegis.gateway.detection.engine.ThreatDetectionEngine;
import com.aegis.gateway.telemetry.ApiEvent;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.connection.stream.*;
import org.springframework.data.redis.core.StreamOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class DetectionStreamConsumerTest {

    private StringRedisTemplate redisTemplate;
    private StreamOperations<String, Object, Object> streamOps;
    private ThreatDetectionEngine detectionEngine;
    private MeterRegistry meterRegistry;
    private DetectionStreamConsumer consumer;

    private final String streamKey = "aegis:stream:api-events";
    private final String groupName = "aegis:group:threat-detection";
    private final String consumerName = "test-worker";

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        streamOps = mock(StreamOperations.class);
        when(redisTemplate.opsForStream()).thenReturn(streamOps);

        detectionEngine = mock(ThreatDetectionEngine.class);
        meterRegistry = new SimpleMeterRegistry();

        consumer = new DetectionStreamConsumer(
            redisTemplate,
            detectionEngine,
            streamKey,
            groupName,
            consumerName,
            50,
            true
        );
        consumer.setMeterRegistry(meterRegistry);
    }

    @Test
    @DisplayName("Should successfully read stream records, invoke detection engine, and acknowledge committed records")
    @SuppressWarnings("unchecked")
    void testProcessBatchAndAcknowledge() {
        RecordId recordId = RecordId.of("1700000000000-0");
        UUID eventId = UUID.randomUUID();
        Map<String, String> fields = new HashMap<>();
        fields.put("id", eventId.toString());
        fields.put("correlationId", "corr-123");
        fields.put("timestamp", Instant.now().toString());
        fields.put("sourceIp", "10.0.0.1");
        fields.put("httpMethod", "GET");
        fields.put("requestPath", "/api/v1/customers/cust-victim-1");
        fields.put("routeId", "customer-service");
        fields.put("statusCode", "403");
        fields.put("latencyMs", "10");
        fields.put("authSubject", "user-1");
        fields.put("authRoles", "ROLE_CUSTOMER");
        fields.put("customerId", "cust-attacker-1");
        fields.put("userAgent", "curl/8.4");
        fields.put("anomalyFlags", "NONE");
        fields.put("resourceType", "CUSTOMER");
        fields.put("resourceId", "cust-victim-1");
        fields.put("errorCode", "BOLA_VIOLATION");
        fields.put("responseSizeBytes", "128");
        fields.put("recordCount", "0");

        MapRecord<String, Object, Object> record = MapRecord.create(
            streamKey,
            (Map<Object, Object>) (Map<?, ?>) fields
        ).withId(recordId);

        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.from("0")))
        )).thenReturn(Collections.emptyList());

        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(List.of(record));

        consumer.pollAndProcess();

        // Verify detection engine was invoked with properly mapped ApiEvent
        ArgumentCaptor<ApiEvent> eventCaptor = ArgumentCaptor.forClass(ApiEvent.class);
        verify(detectionEngine).processEvent(eventCaptor.capture());
        ApiEvent captured = eventCaptor.getValue();
        assertThat(captured.id()).isEqualTo(eventId);
        assertThat(captured.customerId()).isEqualTo("cust-attacker-1");
        assertThat(captured.resourceId()).isEqualTo("cust-victim-1");
        assertThat(captured.errorCode()).isEqualTo("BOLA_VIOLATION");
        assertThat(captured.responseSizeBytes()).isEqualTo(128);

        // Verify record was acknowledged in Redis Stream
        verify(streamOps).acknowledge(eq(streamKey), eq(groupName), eq(recordId));
    }

    @Test
    @DisplayName("Should acknowledge poison message to prevent consumer blocking while logging error")
    @SuppressWarnings("unchecked")
    void testPoisonMessageDoesNotBlockConsumer() {
        RecordId poisonId = RecordId.of("1700000000001-0");
        Map<String, String> badFields = new HashMap<>();
        badFields.put("id", "NOT-A-UUID"); // Deserialization failure

        MapRecord<String, Object, Object> badRecord = MapRecord.create(
            streamKey,
            (Map<Object, Object>) (Map<?, ?>) badFields
        ).withId(poisonId);

        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.from("0")))
        )).thenReturn(Collections.emptyList());

        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(List.of(badRecord));

        consumer.pollAndProcess();

        // Verify acknowledged so stream does not hang
        verify(streamOps).acknowledge(eq(streamKey), eq(groupName), eq(poisonId));
        // Verify poison pill counter incremented
        assertThat(meterRegistry.counter("aegis.detection.consumer.errors", "stage", "poison_pill").count())
            .isEqualTo(1.0);
    }

    @Test
    @DisplayName("Should recover unacknowledged pending messages upon worker restart")
    @SuppressWarnings("unchecked")
    void testRecoverPendingMessagesOnStartup() {
        RecordId pendingRecordId = RecordId.of("1700000000002-0");
        UUID eventId = UUID.randomUUID();
        Map<String, String> fields = new HashMap<>();
        fields.put("id", eventId.toString());
        fields.put("statusCode", "403");
        fields.put("customerId", "cust-recovered-1");
        fields.put("resourceId", "cust-victim-2");

        MapRecord<String, Object, Object> pendingRecord = MapRecord.create(
            streamKey,
            (Map<Object, Object>) (Map<?, ?>) fields
        ).withId(pendingRecordId);

        // Return pending record for offset "0", empty for lastConsumed
        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.from("0")))
        )).thenReturn(List.of(pendingRecord));

        when(streamOps.read(
            any(Consumer.class),
            any(StreamReadOptions.class),
            eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))
        )).thenReturn(Collections.emptyList());

        consumer.pollAndProcess();

        // Verify pending message was processed by detection engine
        verify(detectionEngine).processEvent(argThat(ev -> ev.id().equals(eventId)));
        // Verify pending record was acknowledged
        verify(streamOps).acknowledge(eq(streamKey), eq(groupName), eq(pendingRecordId));
    }

    @Test
    @DisplayName("Should claim stranded pending messages from another dead consumer via XCLAIM")
    @SuppressWarnings("unchecked")
    void testClaimStrandedPendingMessagesFromDeadConsumer() {
        RecordId strandedId = RecordId.of("1700000000003-0");
        UUID eventId = UUID.randomUUID();
        Map<String, String> fields = new HashMap<>();
        fields.put("id", eventId.toString());
        fields.put("statusCode", "403");
        fields.put("customerId", "cust-recovered-2");
        fields.put("resourceId", "cust-victim-3");

        MapRecord<String, Object, Object> claimedRecord = MapRecord.create(
            streamKey,
            (Map<Object, Object>) (Map<?, ?>) fields
        ).withId(strandedId);

        // Pending message assigned to dead worker-crashed-1, idle for 10 seconds
        org.springframework.data.redis.connection.stream.PendingMessage pm = new org.springframework.data.redis.connection.stream.PendingMessage(
            strandedId,
            Consumer.from(groupName, "worker-crashed-1"),
            Duration.ofSeconds(10),
            1L
        );
        org.springframework.data.redis.connection.stream.PendingMessages pms = new org.springframework.data.redis.connection.stream.PendingMessages(
            groupName,
            List.of(pm)
        );

        when(streamOps.read(any(Consumer.class), any(StreamReadOptions.class), eq(StreamOffset.create(streamKey, ReadOffset.from("0")))))
            .thenReturn(Collections.emptyList());
        when(streamOps.read(any(Consumer.class), any(StreamReadOptions.class), eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))))
            .thenReturn(Collections.emptyList());

        when(streamOps.pending(eq(streamKey), eq(groupName), any(org.springframework.data.domain.Range.class), anyLong()))
            .thenReturn(pms);

        when(streamOps.claim(eq(streamKey), eq(groupName), eq(consumerName), any(Duration.class), eq(strandedId)))
            .thenReturn(List.of(claimedRecord));

        consumer.pollAndProcess();

        // Verify claimed record was processed and acknowledged
        verify(detectionEngine).processEvent(argThat(ev -> ev.id().equals(eventId)));
        verify(streamOps).acknowledge(eq(streamKey), eq(groupName), eq(strandedId));
    }

    @Test
    @DisplayName("Should acknowledge and drop poison pills exceeding max delivery count in PEL")
    void testPoisonPillInPelIsAcknowledgedAndDropped() {
        RecordId poisonPelId = RecordId.of("1700000000004-0");

        // Pending message with delivery count = 6 (> maxDeliveries 5)
        org.springframework.data.redis.connection.stream.PendingMessage pm = new org.springframework.data.redis.connection.stream.PendingMessage(
            poisonPelId,
            Consumer.from(groupName, "worker-dead-1"),
            Duration.ofSeconds(60),
            6L // Exceeds maxDeliveries (5)
        );
        org.springframework.data.redis.connection.stream.PendingMessages pms = new org.springframework.data.redis.connection.stream.PendingMessages(
            groupName,
            List.of(pm)
        );

        when(streamOps.read(any(Consumer.class), any(StreamReadOptions.class), eq(StreamOffset.create(streamKey, ReadOffset.from("0")))))
            .thenReturn(Collections.emptyList());
        when(streamOps.read(any(Consumer.class), any(StreamReadOptions.class), eq(StreamOffset.create(streamKey, ReadOffset.lastConsumed()))))
            .thenReturn(Collections.emptyList());

        when(streamOps.pending(eq(streamKey), eq(groupName), any(org.springframework.data.domain.Range.class), anyLong()))
            .thenReturn(pms);

        consumer.pollAndProcess();

        // Verify poison pill was acknowledged to unblock the PEL without processing
        verify(streamOps).acknowledge(eq(streamKey), eq(groupName), eq(poisonPelId));
        assertThat(meterRegistry.counter("aegis.detection.consumer.errors", "stage", "pel_poison_pill").count())
            .isEqualTo(1.0);
    }
}
