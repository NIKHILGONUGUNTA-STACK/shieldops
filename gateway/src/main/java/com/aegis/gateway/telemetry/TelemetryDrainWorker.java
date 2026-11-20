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
    private int pollCycle = 0;

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
            recoverPendingMessages();
        } catch (Exception e) {
            if (isBusyGroupException(e)) {
                groupInitialized = true;
                log.info("Consumer Group {} already exists for stream {}", DRAIN_GROUP, streamKey);
                recoverPendingMessages();
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
            pollCycle++;
            log.info("TelemetryDrainWorker polling stream {}", streamKey);

            // Every 10 polling cycles, recover unacknowledged pending messages from PEL
            if (pollCycle % 10 == 0) {
                recoverPendingMessages();
            }

            List<MapRecord<String, Object, Object>> records = redisTemplate.opsForStream().read(
                Consumer.from(DRAIN_GROUP, DRAIN_CONSUMER),
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.create(streamKey, ReadOffset.lastConsumed())
            );

            if (records == null || records.isEmpty()) {
                return;
            }

            processRecords(records);
        } catch (Exception e) {
            log.error("Telemetry stream drain skipped or failed: {}", e.getMessage(), e);
        }
    }

    public void recoverPendingMessages() {
        try {
            List<MapRecord<String, Object, Object>> pending = redisTemplate.opsForStream().read(
                Consumer.from(DRAIN_GROUP, DRAIN_CONSUMER),
                StreamReadOptions.empty().count(batchSize),
                StreamOffset.create(streamKey, ReadOffset.from("0"))
            );

            if (pending != null && !pending.isEmpty()) {
                log.info("TelemetryDrainWorker recovering {} pending unacknowledged records from offset 0", pending.size());
                processRecords(pending);
            }
        } catch (Exception e) {
            log.debug("TelemetryDrainWorker pending message recovery skipped: {}", e.getMessage());
        }
    }

    private void processRecords(List<MapRecord<String, Object, Object>> records) {
        List<ApiEvent> events = new ArrayList<>();
        List<RecordId> ackIds = new ArrayList<>();
        List<RecordId> malformedIds = new ArrayList<>();

        for (MapRecord<String, Object, Object> record : records) {
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
                String observedFields = (String) value.get("observedFields");
                Integer pageNumber = value.get("pageNumber") != null ? Integer.parseInt(value.get("pageNumber").toString()) : null;
                Integer pageSize = value.get("pageSize") != null ? Integer.parseInt(value.get("pageSize").toString()) : null;
                String simulationRunId = (String) value.get("simulationRunId");
                String simulationCampaignId = (String) value.get("simulationCampaignId");
                String simulationScenarioId = (String) value.get("simulationScenarioId");
                String simulationStage = (String) value.get("simulationStage");
                String tenantId = (String) value.get("tenantId");
                String serviceName = (String) value.get("serviceName");

                events.add(new ApiEvent(
                    id, correlationId, timestamp, sourceIp, httpMethod, requestPath,
                    routeId, statusCode, latencyMs, authSubject, authRoles, customerId,
                    userAgent, payloadHash, anomalyFlags, resourceType, resourceId,
                    errorCode, responseSizeBytes, recordCount, observedFields, pageNumber, pageSize,
                    simulationRunId, simulationCampaignId, simulationScenarioId, simulationStage,
                    tenantId, serviceName
                ));
                ackIds.add(record.getId());
            } catch (Exception e) {
                log.warn("Poison/malformed telemetry record {}: skipping and acknowledging to avoid PEL freeze: {}",
                    record.getId(), e.getMessage());
                malformedIds.add(record.getId());
            }
        }

        if (!events.isEmpty()) {
            repository.saveAll(events);
            redisTemplate.opsForStream().acknowledge(streamKey, DRAIN_GROUP, ackIds.toArray(new RecordId[0]));
            redisTemplate.opsForStream().trim(streamKey, 10000);
            log.debug("Drained and persisted {} API telemetry events from Redis stream", events.size());
        }

        if (!malformedIds.isEmpty()) {
            redisTemplate.opsForStream().acknowledge(streamKey, DRAIN_GROUP, malformedIds.toArray(new RecordId[0]));
            log.info("Acknowledged {} malformed/poison telemetry records", malformedIds.size());
        }
    }
}
