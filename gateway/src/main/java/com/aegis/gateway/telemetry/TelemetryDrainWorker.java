package com.aegis.gateway.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class TelemetryDrainWorker {
    private static final Logger log = LoggerFactory.getLogger(TelemetryDrainWorker.class);

    public static final String DRAIN_GROUP = "aegis:group:telemetry-drain";
    public static final String DRAIN_CONSUMER = "gateway-telemetry-drain-1";

    private final StringRedisTemplate redisTemplate;
    private final ApiEventRepository repository;
    private final String streamKey;
    private final int batchSize;
    private boolean groupInitialized = false;

    public TelemetryDrainWorker(
            StringRedisTemplate redisTemplate,
            ApiEventRepository repository,
            @Value("${aegis.telemetry.redis-stream:aegis:stream:api-events}") String streamKey,
            @Value("${aegis.telemetry.batch-size:50}") int batchSize) {
        this.redisTemplate = redisTemplate;
        this.repository = repository;
        this.streamKey = streamKey;
        this.batchSize = batchSize;
    }

    @PostConstruct
    public void initGroup() {
        ensureGroupCreated();
    }

    private void ensureGroupCreated() {
        try {
            redisTemplate.opsForStream().createGroup(streamKey, ReadOffset.from("0"), DRAIN_GROUP);
            groupInitialized = true;
            log.info("Initialized telemetry drain consumer group {} on stream {}", DRAIN_GROUP, streamKey);
        } catch (Exception e) {
            if (isBusyGroupException(e)) {
                groupInitialized = true;
                log.info("Consumer Group {} already exists for stream {}", DRAIN_GROUP, streamKey);
            } else {
                log.warn("Telemetry drain group init deferred: {}", e.getMessage(), e);
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

    @Scheduled(fixedDelayString = "${aegis.telemetry.drain-interval-ms:2000}")
    public void drainStream() {
        if (!groupInitialized) {
            ensureGroupCreated();
            if (!groupInitialized) return;
        }

        try {
            log.info("TelemetryDrainWorker polling stream {}", streamKey);
            List<MapRecord<String, Object, Object>> records = redisTemplate.opsForStream().read(
                Consumer.from(DRAIN_GROUP, DRAIN_CONSUMER),
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.create(streamKey, ReadOffset.lastConsumed())
            );

            if (records == null || records.isEmpty()) {
                return;
            }

            List<ApiEvent> events = new ArrayList<>();
            List<RecordId> recordIds = new ArrayList<>();

            for (MapRecord<String, Object, Object> record : records) {
                recordIds.add(record.getId());
                Map<Object, Object> value = record.getValue();

                try {
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

                    events.add(new ApiEvent(
                        id, correlationId, timestamp, sourceIp, httpMethod, requestPath,
                        routeId, statusCode, latencyMs, authSubject, authRoles, customerId,
                        userAgent, payloadHash, anomalyFlags, resourceType, resourceId,
                        errorCode, responseSizeBytes, recordCount
                    ));
                } catch (Exception e) {
                    log.debug("Skipping malformed telemetry record: {}", e.getMessage());
                }
            }

            if (!events.isEmpty()) {
                repository.saveAll(events);
                redisTemplate.opsForStream().acknowledge(streamKey, DRAIN_GROUP, recordIds.toArray(new RecordId[0]));
                // Trim stream buffer to keep memory bounded at 10,000 events
                redisTemplate.opsForStream().trim(streamKey, 10000);
                log.debug("Drained and persisted {} API telemetry events from Redis stream", events.size());
            }
        } catch (Exception e) {
            log.error("Telemetry stream drain skipped or failed: {}", e.getMessage(), e);
        }
    }
}
