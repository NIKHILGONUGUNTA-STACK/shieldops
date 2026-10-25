package com.aegis.gateway.detection.consumer;

import com.aegis.gateway.detection.engine.ThreatDetectionEngine;
import com.aegis.gateway.telemetry.ApiEvent;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

@Component
public class DetectionStreamConsumer {
    private static final Logger log = LoggerFactory.getLogger(DetectionStreamConsumer.class);

    public static final String DEFAULT_GROUP_NAME = "aegis:group:threat-detection";
    public static final String DEFAULT_CONSUMER_NAME = "gateway-detection-worker-1";

    private final StringRedisTemplate redisTemplate;
    private final ThreatDetectionEngine detectionEngine;
    private final String streamKey;
    private final String groupName;
    private final String consumerName;
    private final int batchSize;
    private final boolean enabled;

    private MeterRegistry meterRegistry;
    private boolean groupInitialized = false;
    private int pollCycle = 0;

    public DetectionStreamConsumer(
            StringRedisTemplate redisTemplate,
            ThreatDetectionEngine detectionEngine,
            @Value("${aegis.telemetry.redis-stream:aegis:stream:api-events}") String streamKey,
            @Value("${aegis.detection.consumer.group:" + DEFAULT_GROUP_NAME + "}") String groupName,
            @Value("${aegis.detection.consumer.name:" + DEFAULT_CONSUMER_NAME + "}") String consumerName,
            @Value("${aegis.detection.consumer.batch-size:50}") int batchSize,
            @Value("${aegis.detection.consumer.enabled:true}") boolean enabled) {
        this.redisTemplate = redisTemplate;
        this.detectionEngine = detectionEngine;
        this.streamKey = streamKey;
        this.groupName = groupName;
        this.consumerName = consumerName;
        this.batchSize = batchSize;
        this.enabled = enabled;
    }

    @Autowired(required = false)
    public void setMeterRegistry(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void initConsumerGroup() {
        if (!enabled) return;
        ensureGroupCreated();
    }

    private void ensureGroupCreated() {
        try {
            redisTemplate.opsForStream().createGroup(streamKey, ReadOffset.from("0"), groupName);
            groupInitialized = true;
            log.info("Created Redis Stream Consumer Group {} for stream {}", groupName, streamKey);
        } catch (Exception e) {
            if (isBusyGroupException(e)) {
                groupInitialized = true;
                log.info("Consumer Group {} already exists for stream {}", groupName, streamKey);
            } else {
                log.warn("Could not initialize consumer group yet: {}", e.getMessage(), e);
            }
        }
    }

    private boolean isBusyGroupException(Throwable t) {
        while (t != null) {
            String msg = t.getMessage();
            if (msg != null && (msg.contains("BUSYGROUP") || msg.contains("already exists"))) {
                return true;
            }
            if (t.getClass().getName().contains("Busy")) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }

    @Scheduled(fixedDelayString = "${aegis.detection.consumer.poll-interval-ms:1000}")
    public void pollAndProcess() {
        if (!enabled) return;

        if (!groupInitialized) {
            ensureGroupCreated();
            if (!groupInitialized) return;
        }

        try {
            pollCycle++;
            log.debug("DetectionStreamConsumer poll cycle {}, reading from stream {}", pollCycle, streamKey);
            // Every 10 polling cycles, check for pending messages (recovery from crash/restart)
            if (pollCycle % 10 == 0) {
                recoverPendingMessages();
            }

            // Read new unread messages for consumer group
            List<MapRecord<String, Object, Object>> records = redisTemplate.opsForStream().read(
                Consumer.from(groupName, consumerName),
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.create(streamKey, ReadOffset.lastConsumed())
            );

            if (records == null || records.isEmpty()) {
                return;
            }

            processBatch(records);
        } catch (Exception e) {
            log.error("Detection stream poll skipped or encountered error: {}", e.getMessage(), e);
            if (meterRegistry != null) {
                meterRegistry.counter("aegis.detection.consumer.errors", "stage", "poll").increment();
            }
        }
    }

    private void recoverPendingMessages() {
        try {
            // Read unacknowledged messages assigned to this consumer starting from offset 0
            List<MapRecord<String, Object, Object>> pending = redisTemplate.opsForStream().read(
                Consumer.from(groupName, consumerName),
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.create(streamKey, ReadOffset.from("0"))
            );

            if (pending != null && !pending.isEmpty()) {
                log.info("Recovering {} pending unacknowledged telemetry records", pending.size());
                processBatch(pending);
            }
        } catch (Exception e) {
            log.debug("Pending message recovery skipped: {}", e.getMessage());
        }
    }

    private void processBatch(List<MapRecord<String, Object, Object>> records) {
        List<RecordId> ackIds = new ArrayList<>();

        for (MapRecord<String, Object, Object> record : records) {
            try {
                ApiEvent event = parseRecord(record);
                if (event != null) {
                    detectionEngine.processEvent(event);
                    if (meterRegistry != null) {
                        meterRegistry.counter("aegis.detection.events.processed").increment();
                    }
                }
                // Only queue for acknowledgement if processed without exception
                ackIds.add(record.getId());
            } catch (Exception e) {
                log.error("Poison message or evaluation error on record {}: {}", record.getId(), e.getMessage());
                // In case of a persistent deserialization failure (poison pill), acknowledge to prevent stream freeze
                ackIds.add(record.getId());
                if (meterRegistry != null) {
                    meterRegistry.counter("aegis.detection.consumer.errors", "stage", "poison_pill").increment();
                }
            }
        }

        if (!ackIds.isEmpty()) {
            try {
                redisTemplate.opsForStream().acknowledge(streamKey, groupName, ackIds.toArray(new RecordId[0]));
                log.trace("Acknowledged {} records for consumer group {}", ackIds.size(), groupName);
            } catch (Exception e) {
                log.error("Failed to acknowledge stream records: {}", e.getMessage());
            }
        }
    }

    private ApiEvent parseRecord(MapRecord<String, Object, Object> record) {
        Map<Object, Object> value = record.getValue();
        if (value == null || value.isEmpty()) return null;

        UUID id = UUID.fromString(value.getOrDefault("id", UUID.randomUUID().toString()).toString());
        String correlationId = value.getOrDefault("correlationId", "").toString();
        Instant timestamp = Instant.parse(value.getOrDefault("timestamp", Instant.now().toString()).toString());
        String sourceIp = value.getOrDefault("sourceIp", "127.0.0.1").toString();
        String httpMethod = value.getOrDefault("httpMethod", "GET").toString();
        String requestPath = value.getOrDefault("requestPath", "/").toString();
        String routeId = value.getOrDefault("routeId", "").toString();
        int statusCode = Integer.parseInt(value.getOrDefault("statusCode", "200").toString());
        long latencyMs = Long.parseLong(value.getOrDefault("latencyMs", "0").toString());
        String authSubject = value.getOrDefault("authSubject", "").toString();
        String authRoles = value.getOrDefault("authRoles", "").toString();
        String customerId = value.getOrDefault("customerId", "").toString();
        String userAgent = value.getOrDefault("userAgent", "").toString();
        String payloadHash = (String) value.get("payloadHash");
        String anomalyFlags = value.getOrDefault("anomalyFlags", "NONE").toString();

        String resourceType = (String) value.get("resourceType");
        String resourceId = (String) value.get("resourceId");
        String errorCode = (String) value.get("errorCode");
        long responseSizeBytes = Long.parseLong(value.getOrDefault("responseSizeBytes", "0").toString());
        int recordCount = Integer.parseInt(value.getOrDefault("recordCount", "0").toString());

        return new ApiEvent(
            id, correlationId, timestamp, sourceIp, httpMethod, requestPath,
            routeId, statusCode, latencyMs, authSubject, authRoles, customerId,
            userAgent, payloadHash, anomalyFlags, resourceType, resourceId,
            errorCode, responseSizeBytes, recordCount
        );
    }
}
