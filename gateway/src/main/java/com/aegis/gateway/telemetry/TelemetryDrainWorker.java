package com.aegis.gateway.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.MapRecord;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamOffset;
import org.springframework.data.redis.connection.stream.StreamReadOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class TelemetryDrainWorker {
    private static final Logger log = LoggerFactory.getLogger(TelemetryDrainWorker.class);

    private final StringRedisTemplate redisTemplate;
    private final ApiEventRepository repository;
    private final String streamKey;
    private final int batchSize;

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

    @Scheduled(fixedDelayString = "${aegis.telemetry.drain-interval-ms:2000}")
    public void drainStream() {
        try {
            List<MapRecord<String, Object, Object>> records = redisTemplate.opsForStream().read(
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.fromStart(streamKey)
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

                    events.add(new ApiEvent(
                        id, correlationId, timestamp, sourceIp, httpMethod, requestPath,
                        routeId, statusCode, latencyMs, authSubject, authRoles, customerId,
                        userAgent, payloadHash, anomalyFlags
                    ));
                } catch (Exception e) {
                    log.debug("Skipping malformed telemetry record: {}", e.getMessage());
                }
            }

            if (!events.isEmpty()) {
                repository.saveAll(events);
                redisTemplate.opsForStream().delete(streamKey, recordIds.toArray(new RecordId[0]));
                log.debug("Drained and persisted {} API telemetry events from Redis stream", events.size());
            }
        } catch (Exception e) {
            log.trace("Telemetry stream drain skipped or failed: {}", e.getMessage());
        }
    }
}
