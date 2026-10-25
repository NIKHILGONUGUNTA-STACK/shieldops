package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class RedisDetectionStateStore implements DetectionStateStore {
    private static final Logger log = LoggerFactory.getLogger(RedisDetectionStateStore.class);
    private static final String KEY_PREFIX = "aegis:state:bola:";

    private final StringRedisTemplate redisTemplate;
    // Resilient in-memory fallback for local tests and Redis outages
    private final Map<String, List<BolaAttemptRecord>> memoryFallback = new ConcurrentHashMap<>();

    public RedisDetectionStateStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp) {
        if (customerId == null || customerId.isBlank()) return;

        String key = KEY_PREFIX + customerId.trim();
        String member = eventId.toString() + ":" + (resourceId != null ? resourceId.trim() : "UNKNOWN");
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            // Expire key after 1 hour of inactivity to avoid Redis memory leaks
            redisTemplate.expire(key, java.time.Duration.ofHours(1));
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using memory fallback: {}", e.getMessage());
            memoryFallback.computeIfAbsent(customerId.trim(), k -> new CopyOnWriteArrayList<>())
                .add(new BolaAttemptRecord(eventId, resourceId, timestamp));
        }
    }

    @Override
    public List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since) {
        if (customerId == null || customerId.isBlank()) return Collections.emptyList();

        String key = KEY_PREFIX + customerId.trim();
        double minScore = since.toEpochMilli();
        double maxScore = Double.POSITIVE_INFINITY;

        try {
            // Trim entries older than 'since' to bound set size
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, minScore - 1);
            Set<ZSetOperations.TypedTuple<String>> tuples = redisTemplate.opsForZSet()
                .rangeByScoreWithScores(key, minScore, maxScore);

            if (tuples == null || tuples.isEmpty()) {
                return Collections.emptyList();
            }

            List<BolaAttemptRecord> results = new ArrayList<>();
            for (ZSetOperations.TypedTuple<String> tuple : tuples) {
                String val = tuple.getValue();
                if (val != null) {
                    int colonIdx = val.indexOf(':');
                    if (colonIdx > 0) {
                        try {
                            UUID eventId = UUID.fromString(val.substring(0, colonIdx));
                            String resourceId = val.substring(colonIdx + 1);
                            Instant ts = Instant.ofEpochMilli(tuple.getScore().longValue());
                            results.add(new BolaAttemptRecord(eventId, resourceId, ts));
                        } catch (Exception parseEx) {
                            log.debug("Malformed ZSet value: {}", val);
                        }
                    }
                }
            }
            return results;
        } catch (Exception e) {
            log.debug("Redis state query failed, querying memory fallback: {}", e.getMessage());
            List<BolaAttemptRecord> inMem = memoryFallback.getOrDefault(customerId.trim(), Collections.emptyList());
            return inMem.stream()
                .filter(r -> !r.timestamp().isBefore(since))
                .toList();
        }
    }

    @Override
    public void clear(String customerId) {
        if (customerId == null) return;
        try {
            redisTemplate.delete(KEY_PREFIX + customerId.trim());
        } catch (Exception ignored) {}
        memoryFallback.remove(customerId.trim());
    }
}
