package com.aegis.gateway.detection.consumer;

import com.aegis.gateway.detection.engine.ThreatDetectionEngine;
import com.aegis.gateway.telemetry.ApiEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Range;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.stream.*;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.*;

class DetectionConsumerRedisIntegrationTest {

    private LettuceConnectionFactory connectionFactory;
    private StringRedisTemplate redisTemplate;
    private String testStreamKey;
    private String testGroupName;

    @BeforeEach
    void setUp() {
        try {
            RedisStandaloneConfiguration config = new RedisStandaloneConfiguration("localhost", 6379);
            connectionFactory = new LettuceConnectionFactory(config);
            connectionFactory.afterPropertiesSet();
            redisTemplate = new StringRedisTemplate(connectionFactory);
            String ping = redisTemplate.getConnectionFactory().getConnection().ping();
            assumeTrue("PONG".equalsIgnoreCase(ping), "Redis server not available on localhost:6379");
        } catch (Exception e) {
            assumeTrue(false, "Redis connection failed: " + e.getMessage());
        }

        testStreamKey = "test:stream:recovery-" + UUID.randomUUID();
        testGroupName = "test:group:recovery-" + UUID.randomUUID();
    }

    @AfterEach
    void tearDown() {
        if (redisTemplate != null) {
            try {
                redisTemplate.delete(testStreamKey);
            } catch (Exception ignored) {}
        }
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Test
    @DisplayName("Live Redis: Should verify unacknowledged pending message in PEL and claim ownership across consumer restart")
    void testLiveRedisPendingMessageRecoveryAndClaim() {
        ThreatDetectionEngine engineA = mock(ThreatDetectionEngine.class);
        ThreatDetectionEngine engineB = mock(ThreatDetectionEngine.class);

        // 1. Initialize consumer group on stream
        redisTemplate.opsForStream().createGroup(testStreamKey, ReadOffset.from("0"), testGroupName);

        // 2. Publish an API event into the stream
        UUID eventId = UUID.randomUUID();
        Map<String, String> eventFields = new HashMap<>();
        eventFields.put("id", eventId.toString());
        eventFields.put("correlationId", "corr-test-1");
        eventFields.put("timestamp", Instant.now().toString());
        eventFields.put("sourceIp", "127.0.0.1");
        eventFields.put("httpMethod", "GET");
        eventFields.put("requestPath", "/api/v1/customers/victim-1");
        eventFields.put("routeId", "/api/v1/customers/{id}");
        eventFields.put("statusCode", "403");
        eventFields.put("latencyMs", "12");
        eventFields.put("customerId", "cust-attacker-1");
        eventFields.put("resourceType", "CUSTOMER");
        eventFields.put("resourceId", "victim-1");

        RecordId recordId = redisTemplate.opsForStream().add(testStreamKey, eventFields);
        assertThat(recordId).isNotNull();

        // 3. Consumer 1 ("worker-crashed-1") reads the message but NEVER acknowledges it (simulating crash)
        List<MapRecord<String, Object, Object>> readByWorker1 = redisTemplate.opsForStream().read(
            Consumer.from(testGroupName, "worker-crashed-1"),
            StreamReadOptions.empty().count(10),
            StreamOffset.create(testStreamKey, ReadOffset.lastConsumed())
        );
        assertThat(readByWorker1).hasSize(1);
        assertThat(readByWorker1.get(0).getId()).isEqualTo(recordId);

        // 4. Verify the message is now in the PEL (Pending Entries List) assigned to worker-crashed-1
        PendingMessages pelBefore = redisTemplate.opsForStream().pending(
            testStreamKey,
            testGroupName,
            Range.unbounded(),
            10
        );
        assertThat(pelBefore).isNotEmpty();
        PendingMessage pm = pelBefore.get(0);
        assertThat(pm.getId()).isEqualTo(recordId);
        assertThat(pm.getConsumerName()).isEqualTo("worker-crashed-1");

        // 5. Worker 2 ("worker-restarted-2") starts up with minIdleMs = 0 (immediate claim of dead consumer work)
        DetectionStreamConsumer consumerB = new DetectionStreamConsumer(
            redisTemplate,
            engineB,
            testStreamKey,
            testGroupName,
            "worker-restarted-2",
            10,
            true,
            0L, // minIdleMs = 0 to claim immediately in test
            5L
        );

        // Run recovery routine
        consumerB.recoverPendingMessages();

        // 6. Verify worker 2 successfully claimed and processed the event
        ArgumentCaptor<ApiEvent> eventCaptor = ArgumentCaptor.forClass(ApiEvent.class);
        verify(engineB).processEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().id()).isEqualTo(eventId);
        assertThat(eventCaptor.getValue().customerId()).isEqualTo("cust-attacker-1");

        // 7. Verify the message was acknowledged and PEL is now completely empty
        PendingMessages pelAfter = redisTemplate.opsForStream().pending(
            testStreamKey,
            testGroupName,
            Range.unbounded(),
            10
        );
        assertThat(pelAfter).isEmpty();
    }
}
