package com.aegis.gateway.detection.state;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DataVolumeRecord;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.SlidingWindowEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis-backed sliding-window detection state store with bounded in-memory fallback.
 * Manages separate, documented state keys for each threat detection rule with TTL expiration.
 */
@Component
public class RedisDetectionStateStore implements DetectionStateStore {
    private static final Logger log = LoggerFactory.getLogger(RedisDetectionStateStore.class);

    public static final String KEY_PREFIX_BOLA = "aegis:state:bola:";
    public static final String KEY_PREFIX_AUTH = "aegis:state:auth:";
    public static final String KEY_PREFIX_DATA = "aegis:state:data:";
    public static final String KEY_PREFIX_RATE = "aegis:state:rate:";
    public static final String KEY_PREFIX_PROBE = "aegis:state:probe:";
    public static final String KEY_PREFIX_INJ = "aegis:state:inj:";

    private static final Duration DEFAULT_TTL = Duration.ofHours(1);
    private static final int MAX_FALLBACK_SIZE = 500;

    private final StringRedisTemplate redisTemplate;

    // Resilient in-memory fallbacks for unit testing and Redis outage tolerance
    private final Map<String, Map<UUID, BolaAttemptRecord>> bolaFallback = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, SlidingWindowEvent>> authFallback = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, DataVolumeRecord>> dataFallback = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, SlidingWindowEvent>> rateFallback = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, ProbeRecord>> probeFallback = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, SlidingWindowEvent>> injFallback = new ConcurrentHashMap<>();

    public RedisDetectionStateStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // ==========================================
    // 1. RULE-BOLA-01
    // ==========================================

    @Override
    public void recordBolaAttempt(String customerId, UUID eventId, String resourceId, Instant timestamp) {
        if (customerId == null || customerId.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_BOLA + customerId.trim();
        String member = eventId + ":" + (resourceId != null ? resourceId.trim() : "UNKNOWN");
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using bola memory fallback: {}", e.getMessage());
            Map<UUID, BolaAttemptRecord> customerAttempts = bolaFallback.computeIfAbsent(customerId.trim(), k -> new ConcurrentHashMap<>());
            customerAttempts.put(eventId, new BolaAttemptRecord(eventId, resourceId != null ? resourceId.trim() : "UNKNOWN", timestamp));
            pruneMemoryFallback(customerAttempts, timestamp);
        }
    }

    @Override
    public List<BolaAttemptRecord> getRecentBolaAttempts(String customerId, Instant since) {
        if (customerId == null || customerId.isBlank()) return Collections.emptyList();
        String key = KEY_PREFIX_BOLA + customerId.trim();
        double minScore = since.toEpochMilli();

        try {
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, minScore - 1);
            Set<ZSetOperations.TypedTuple<String>> tuples = redisTemplate.opsForZSet()
                .rangeByScoreWithScores(key, minScore, Double.POSITIVE_INFINITY);

            if (tuples == null || tuples.isEmpty()) return Collections.emptyList();

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
                        } catch (Exception ignored) {}
                    }
                }
            }
            return results;
        } catch (Exception e) {
            log.debug("Redis state query failed, querying bola memory fallback: {}", e.getMessage());
            Map<UUID, BolaAttemptRecord> customerAttempts = bolaFallback.get(customerId.trim());
            if (customerAttempts == null || customerAttempts.isEmpty()) return Collections.emptyList();
            customerAttempts.values().removeIf(r -> r.timestamp().isBefore(since));
            return new ArrayList<>(customerAttempts.values());
        }
    }

    @Override
    public void clear(String customerId) {
        if (customerId == null) return;
        try {
            redisTemplate.delete(KEY_PREFIX_BOLA + customerId.trim());
        } catch (Exception ignored) {}
        bolaFallback.remove(customerId.trim());
    }

    // ==========================================
    // 2. RULE-AUTH-01 (Authentication Failures)
    // ==========================================

    @Override
    public void recordAuthFailure(String entityKey, UUID eventId, String route, Instant timestamp) {
        if (entityKey == null || entityKey.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_AUTH + entityKey.trim();
        String member = eventId + ":" + (route != null ? route.trim() : "UNKNOWN");
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using auth memory fallback: {}", e.getMessage());
            Map<UUID, SlidingWindowEvent> attempts = authFallback.computeIfAbsent(entityKey.trim(), k -> new ConcurrentHashMap<>());
            attempts.put(eventId, new SlidingWindowEvent(eventId, route != null ? route.trim() : "UNKNOWN", timestamp));
            pruneGenericFallback(attempts, timestamp);
        }
    }

    @Override
    public List<SlidingWindowEvent> getRecentAuthFailures(String entityKey, Instant since) {
        return queryGenericZSet(KEY_PREFIX_AUTH, entityKey, since, authFallback);
    }

    // ==========================================
    // 3. RULE-DATA-01 (Data Access Metrics)
    // ==========================================

    @Override
    public void recordDataAccess(String customerId, UUID eventId, int recordCount, long responseSizeBytes, Instant timestamp) {
        if (customerId == null || customerId.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_DATA + customerId.trim();
        String member = eventId + ":" + recordCount + ":" + responseSizeBytes;
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using data memory fallback: {}", e.getMessage());
            Map<UUID, DataVolumeRecord> records = dataFallback.computeIfAbsent(customerId.trim(), k -> new ConcurrentHashMap<>());
            records.put(eventId, new DataVolumeRecord(eventId, recordCount, responseSizeBytes, timestamp));
            pruneDataFallback(records, timestamp);
        }
    }

    @Override
    public List<DataVolumeRecord> getRecentDataAccess(String customerId, Instant since) {
        if (customerId == null || customerId.isBlank()) return Collections.emptyList();
        String key = KEY_PREFIX_DATA + customerId.trim();
        double minScore = since.toEpochMilli();

        try {
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, minScore - 1);
            Set<ZSetOperations.TypedTuple<String>> tuples = redisTemplate.opsForZSet()
                .rangeByScoreWithScores(key, minScore, Double.POSITIVE_INFINITY);

            if (tuples == null || tuples.isEmpty()) return Collections.emptyList();

            List<DataVolumeRecord> results = new ArrayList<>();
            for (ZSetOperations.TypedTuple<String> tuple : tuples) {
                String val = tuple.getValue();
                if (val != null) {
                    String[] parts = val.split(":", 3);
                    if (parts.length == 3) {
                        try {
                            UUID eventId = UUID.fromString(parts[0]);
                            int recordCount = Integer.parseInt(parts[1]);
                            long bytes = Long.parseLong(parts[2]);
                            Instant ts = Instant.ofEpochMilli(tuple.getScore().longValue());
                            results.add(new DataVolumeRecord(eventId, recordCount, bytes, ts));
                        } catch (Exception ignored) {}
                    }
                }
            }
            return results;
        } catch (Exception e) {
            log.debug("Redis state query failed, querying data memory fallback: {}", e.getMessage());
            Map<UUID, DataVolumeRecord> records = dataFallback.get(customerId.trim());
            if (records == null || records.isEmpty()) return Collections.emptyList();
            records.values().removeIf(r -> r.timestamp().isBefore(since));
            return new ArrayList<>(records.values());
        }
    }

    // ==========================================
    // 4. RULE-RATE-01 (API Request Bursts)
    // ==========================================

    @Override
    public void recordRequest(String entityKey, UUID eventId, String route, Instant timestamp) {
        if (entityKey == null || entityKey.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_RATE + entityKey.trim();
        String member = eventId + ":" + (route != null ? route.trim() : "UNKNOWN");
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using rate memory fallback: {}", e.getMessage());
            Map<UUID, SlidingWindowEvent> requests = rateFallback.computeIfAbsent(entityKey.trim(), k -> new ConcurrentHashMap<>());
            requests.put(eventId, new SlidingWindowEvent(eventId, route != null ? route.trim() : "UNKNOWN", timestamp));
            pruneGenericFallback(requests, timestamp);
        }
    }

    @Override
    public List<SlidingWindowEvent> getRecentRequests(String entityKey, Instant since) {
        return queryGenericZSet(KEY_PREFIX_RATE, entityKey, since, rateFallback);
    }

    // ==========================================
    // 5. RULE-PROBE-01 (Probing & Validation Errors)
    // ==========================================

    @Override
    public void recordProbeAttempt(String entityKey, UUID eventId, String path, String payloadHash, int statusCode, Instant timestamp) {
        if (entityKey == null || entityKey.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_PROBE + entityKey.trim();
        String safeHash = payloadHash != null ? payloadHash : "NONE";
        String safePath = path != null ? path : "UNKNOWN";
        String member = eventId + ":" + statusCode + ":" + safeHash + ":" + safePath;
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using probe memory fallback: {}", e.getMessage());
            Map<UUID, ProbeRecord> probes = probeFallback.computeIfAbsent(entityKey.trim(), k -> new ConcurrentHashMap<>());
            probes.put(eventId, new ProbeRecord(eventId, safePath, safeHash, statusCode, timestamp));
            pruneProbeFallback(probes, timestamp);
        }
    }

    @Override
    public List<ProbeRecord> getRecentProbeAttempts(String entityKey, Instant since) {
        if (entityKey == null || entityKey.isBlank()) return Collections.emptyList();
        String key = KEY_PREFIX_PROBE + entityKey.trim();
        double minScore = since.toEpochMilli();

        try {
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, minScore - 1);
            Set<ZSetOperations.TypedTuple<String>> tuples = redisTemplate.opsForZSet()
                .rangeByScoreWithScores(key, minScore, Double.POSITIVE_INFINITY);

            if (tuples == null || tuples.isEmpty()) return Collections.emptyList();

            List<ProbeRecord> results = new ArrayList<>();
            for (ZSetOperations.TypedTuple<String> tuple : tuples) {
                String val = tuple.getValue();
                if (val != null) {
                    String[] parts = val.split(":", 4);
                    if (parts.length == 4) {
                        try {
                            UUID eventId = UUID.fromString(parts[0]);
                            int statusCode = Integer.parseInt(parts[1]);
                            String payloadHash = parts[2];
                            String path = parts[3];
                            Instant ts = Instant.ofEpochMilli(tuple.getScore().longValue());
                            results.add(new ProbeRecord(eventId, path, payloadHash, statusCode, ts));
                        } catch (Exception ignored) {}
                    }
                }
            }
            return results;
        } catch (Exception e) {
            log.debug("Redis state query failed, querying probe memory fallback: {}", e.getMessage());
            Map<UUID, ProbeRecord> probes = probeFallback.get(entityKey.trim());
            if (probes == null || probes.isEmpty()) return Collections.emptyList();
            probes.values().removeIf(r -> r.timestamp().isBefore(since));
            return new ArrayList<>(probes.values());
        }
    }

    // ==========================================
    // 6. RULE-INJ-01 (Injection Indicators)
    // ==========================================

    @Override
    public void recordInjectionAttempt(String entityKey, UUID eventId, String patternType, Instant timestamp) {
        if (entityKey == null || entityKey.isBlank() || eventId == null) return;
        String key = KEY_PREFIX_INJ + entityKey.trim();
        String member = eventId + ":" + (patternType != null ? patternType : "UNKNOWN");
        double score = timestamp.toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(key, member, score);
            redisTemplate.expire(key, DEFAULT_TTL);
        } catch (Exception e) {
            log.debug("Redis state store unavailable, using inj memory fallback: {}", e.getMessage());
            Map<UUID, SlidingWindowEvent> injAttempts = injFallback.computeIfAbsent(entityKey.trim(), k -> new ConcurrentHashMap<>());
            injAttempts.put(eventId, new SlidingWindowEvent(eventId, patternType != null ? patternType : "UNKNOWN", timestamp));
            pruneGenericFallback(injAttempts, timestamp);
        }
    }

    @Override
    public List<SlidingWindowEvent> getRecentInjectionAttempts(String entityKey, Instant since) {
        return queryGenericZSet(KEY_PREFIX_INJ, entityKey, since, injFallback);
    }

    // ==========================================
    // Generic Key Deletion & Query Helpers
    // ==========================================

    @Override
    public void clearKey(String prefix, String entityKey) {
        if (entityKey == null) return;
        String trimmed = entityKey.trim();
        try {
            redisTemplate.delete(prefix + trimmed);
        } catch (Exception ignored) {}

        if (KEY_PREFIX_BOLA.equals(prefix)) bolaFallback.remove(trimmed);
        else if (KEY_PREFIX_AUTH.equals(prefix)) authFallback.remove(trimmed);
        else if (KEY_PREFIX_DATA.equals(prefix)) dataFallback.remove(trimmed);
        else if (KEY_PREFIX_RATE.equals(prefix)) rateFallback.remove(trimmed);
        else if (KEY_PREFIX_PROBE.equals(prefix)) probeFallback.remove(trimmed);
        else if (KEY_PREFIX_INJ.equals(prefix)) injFallback.remove(trimmed);
    }

    private List<SlidingWindowEvent> queryGenericZSet(
            String prefix,
            String entityKey,
            Instant since,
            Map<String, Map<UUID, SlidingWindowEvent>> fallbackMap) {
        if (entityKey == null || entityKey.isBlank()) return Collections.emptyList();
        String key = prefix + entityKey.trim();
        double minScore = since.toEpochMilli();

        try {
            redisTemplate.opsForZSet().removeRangeByScore(key, 0, minScore - 1);
            Set<ZSetOperations.TypedTuple<String>> tuples = redisTemplate.opsForZSet()
                .rangeByScoreWithScores(key, minScore, Double.POSITIVE_INFINITY);

            if (tuples == null || tuples.isEmpty()) return Collections.emptyList();

            List<SlidingWindowEvent> results = new ArrayList<>();
            for (ZSetOperations.TypedTuple<String> tuple : tuples) {
                String val = tuple.getValue();
                if (val != null) {
                    int colonIdx = val.indexOf(':');
                    if (colonIdx > 0) {
                        try {
                            UUID eventId = UUID.fromString(val.substring(0, colonIdx));
                            String metadata = val.substring(colonIdx + 1);
                            Instant ts = Instant.ofEpochMilli(tuple.getScore().longValue());
                            results.add(new SlidingWindowEvent(eventId, metadata, ts));
                        } catch (Exception ignored) {}
                    }
                }
            }
            return results;
        } catch (Exception e) {
            log.debug("Redis state query failed for {}, querying memory fallback: {}", key, e.getMessage());
            Map<UUID, SlidingWindowEvent> attempts = fallbackMap.get(entityKey.trim());
            if (attempts == null || attempts.isEmpty()) return Collections.emptyList();
            attempts.values().removeIf(r -> r.timestamp().isBefore(since));
            return new ArrayList<>(attempts.values());
        }
    }

    private void pruneMemoryFallback(Map<UUID, BolaAttemptRecord> map, Instant timestamp) {
        if (map.size() > MAX_FALLBACK_SIZE) {
            Instant cutoff = timestamp.minusSeconds(3600);
            map.values().removeIf(r -> r.timestamp().isBefore(cutoff));
            if (map.size() > MAX_FALLBACK_SIZE) {
                List<BolaAttemptRecord> sorted = new ArrayList<>(map.values());
                sorted.sort(Comparator.comparing(BolaAttemptRecord::timestamp));
                int toRemove = map.size() - MAX_FALLBACK_SIZE;
                for (int i = 0; i < toRemove && i < sorted.size(); i++) {
                    map.remove(sorted.get(i).eventId());
                }
            }
        }
    }

    private void pruneGenericFallback(Map<UUID, SlidingWindowEvent> map, Instant timestamp) {
        if (map.size() > MAX_FALLBACK_SIZE) {
            Instant cutoff = timestamp.minusSeconds(3600);
            map.values().removeIf(r -> r.timestamp().isBefore(cutoff));
            if (map.size() > MAX_FALLBACK_SIZE) {
                List<SlidingWindowEvent> sorted = new ArrayList<>(map.values());
                sorted.sort(Comparator.comparing(SlidingWindowEvent::timestamp));
                int toRemove = map.size() - MAX_FALLBACK_SIZE;
                for (int i = 0; i < toRemove && i < sorted.size(); i++) {
                    map.remove(sorted.get(i).eventId());
                }
            }
        }
    }

    private void pruneDataFallback(Map<UUID, DataVolumeRecord> map, Instant timestamp) {
        if (map.size() > MAX_FALLBACK_SIZE) {
            Instant cutoff = timestamp.minusSeconds(3600);
            map.values().removeIf(r -> r.timestamp().isBefore(cutoff));
            if (map.size() > MAX_FALLBACK_SIZE) {
                List<DataVolumeRecord> sorted = new ArrayList<>(map.values());
                sorted.sort(Comparator.comparing(DataVolumeRecord::timestamp));
                int toRemove = map.size() - MAX_FALLBACK_SIZE;
                for (int i = 0; i < toRemove && i < sorted.size(); i++) {
                    map.remove(sorted.get(i).eventId());
                }
            }
        }
    }

    private void pruneProbeFallback(Map<UUID, ProbeRecord> map, Instant timestamp) {
        if (map.size() > MAX_FALLBACK_SIZE) {
            Instant cutoff = timestamp.minusSeconds(3600);
            map.values().removeIf(r -> r.timestamp().isBefore(cutoff));
            if (map.size() > MAX_FALLBACK_SIZE) {
                List<ProbeRecord> sorted = new ArrayList<>(map.values());
                sorted.sort(Comparator.comparing(ProbeRecord::timestamp));
                int toRemove = map.size() - MAX_FALLBACK_SIZE;
                for (int i = 0; i < toRemove && i < sorted.size(); i++) {
                    map.remove(sorted.get(i).eventId());
                }
            }
        }
    }
}
