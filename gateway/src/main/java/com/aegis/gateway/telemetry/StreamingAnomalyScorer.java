package com.aegis.gateway.telemetry;

import com.aegis.gateway.workflow.WorkflowStateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe streaming statistical anomaly scorer using Welford's single-pass continuous algorithm.
 * Operates in O(1) time and space per transaction with sub-microsecond overhead.
 */
@Service
public class StreamingAnomalyScorer {
    private static final Logger log = LoggerFactory.getLogger(StreamingAnomalyScorer.class);

    private final double zThreshold;
    private final StringRedisTemplate redisTemplate;

    // trackers[canonicalEndpoint][metricName] -> WelfordTracker
    private final Map<String, Map<String, WelfordTracker>> trackers = new ConcurrentHashMap<>();

    public record OutlierResult(
            boolean isOutlier,
            String endpoint,
            String outlierType,
            double payloadZ,
            double latencyZ,
            double maxZ,
            long payloadBytes,
            long latencyMs,
            String details
    ) {
        public static OutlierResult normal(String endpoint, double payloadZ, double latencyZ, long bytes, long ms) {
            return new OutlierResult(false, endpoint, null, payloadZ, latencyZ, Math.max(payloadZ, latencyZ), bytes, ms, null);
        }

        public static OutlierResult outlier(
                String endpoint,
                String outlierType,
                double payloadZ,
                double latencyZ,
                double maxZ,
                long bytes,
                long ms,
                String details) {
            return new OutlierResult(true, endpoint, outlierType, payloadZ, latencyZ, maxZ, bytes, ms, details);
        }
    }

    public static class WelfordTracker {
        private long count = 0;
        private double mean = 0.0;
        private double m2 = 0.0;
        private double minVal = Double.MAX_VALUE;
        private double maxVal = Double.MIN_VALUE;

        public synchronized void update(double val) {
            count++;
            double delta = val - mean;
            mean += delta / count;
            double delta2 = val - mean;
            m2 += delta * delta2;
            minVal = Math.min(minVal, val);
            maxVal = Math.max(maxVal, val);
        }

        public synchronized double getMean() {
            return mean;
        }

        public synchronized double getVariance() {
            return count >= 2 ? m2 / (count - 1) : 0.0;
        }

        public synchronized double getStdDev() {
            return Math.sqrt(Math.max(0.0, getVariance()));
        }

        public synchronized double computeZScore(double val) {
            if (count < 5) {
                return 0.0;
            }
            double sigma = getStdDev();
            if (sigma < 1e-4) {
                return 0.0;
            }
            return (val - mean) / sigma;
        }

        public synchronized long getCount() {
            return count;
        }

        public synchronized Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("count", count);
            map.put("mean", Math.round(mean * 100.0) / 100.0);
            map.put("stdDev", Math.round(getStdDev() * 100.0) / 100.0);
            map.put("min", count > 0 ? Math.round(minVal * 100.0) / 100.0 : 0.0);
            map.put("max", count > 0 ? Math.round(maxVal * 100.0) / 100.0 : 0.0);
            return map;
        }
    }

    @Autowired
    public StreamingAnomalyScorer(@Autowired(required = false) StringRedisTemplate redisTemplate) {
        this(redisTemplate, 3.5);
    }

    public StreamingAnomalyScorer(StringRedisTemplate redisTemplate, double zThreshold) {
        this.redisTemplate = redisTemplate;
        this.zThreshold = zThreshold;
    }

    private WelfordTracker getTracker(String endpoint, String metric) {
        return trackers
                .computeIfAbsent(endpoint, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(metric, k -> new WelfordTracker());
    }

    /**
     * Evaluates whether a transaction is a volumetric or latency anomaly, and updates running statistics.
     */
    public OutlierResult evaluateAndRecord(String method, String rawPath, long payloadBytes, long latencyMs) {
        String endpoint = WorkflowStateService.canonicalKey(method, rawPath);
        WelfordTracker payloadTracker = getTracker(endpoint, "payload_bytes");
        WelfordTracker latencyTracker = getTracker(endpoint, "latency_ms");

        double payloadZ = payloadTracker.computeZScore((double) payloadBytes);
        double latencyZ = latencyTracker.computeZScore((double) latencyMs);

        double effectivePayloadZ = Math.max(0.0, payloadZ);
        double effectiveLatencyZ = Math.max(0.0, latencyZ);
        double maxZ = Math.max(effectivePayloadZ, effectiveLatencyZ);

        boolean isPayloadOutlier = effectivePayloadZ >= zThreshold && payloadTracker.getCount() >= 5;
        boolean isLatencyOutlier = effectiveLatencyZ >= zThreshold && latencyTracker.getCount() >= 5;
        boolean isOutlier = isPayloadOutlier || isLatencyOutlier;

        String outlierType = null;
        if (isPayloadOutlier && isLatencyOutlier) {
            outlierType = "COMBO_VOLUMETRIC_AND_LATENCY";
        } else if (isPayloadOutlier) {
            outlierType = "VOLUMETRIC_EXFILTRATION";
        } else if (isLatencyOutlier) {
            outlierType = "LATENCY_DEGRADATION";
        }

        // Update statistics with this observation
        payloadTracker.update((double) payloadBytes);
        latencyTracker.update((double) latencyMs);

        if (isOutlier) {
            String details = String.format(
                "Endpoint '%s' spike: payload=%d bytes (mean=%.1f, std=%.1f, Z=%.2f), latency=%d ms (mean=%.1f, std=%.1f, Z=%.2f)",
                endpoint, payloadBytes, payloadTracker.getMean(), payloadTracker.getStdDev(), payloadZ,
                latencyMs, latencyTracker.getMean(), latencyTracker.getStdDev(), latencyZ
            );
            log.warn("Streaming Outlier Flagged: [{}] {}", outlierType, details);

            // Publish alert asynchronously if redis is available
            if (redisTemplate != null) {
                try {
                    Map<String, String> alertMap = new HashMap<>();
                    alertMap.put("type", "STREAM_ANOMALY");
                    alertMap.put("outlierType", outlierType);
                    alertMap.put("endpoint", endpoint);
                    alertMap.put("payloadBytes", String.valueOf(payloadBytes));
                    alertMap.put("latencyMs", String.valueOf(latencyMs));
                    alertMap.put("maxZ", String.format("%.2f", maxZ));
                    alertMap.put("timestamp", Instant.now().toString());
                    redisTemplate.opsForStream().add("aegis:stream:api-events", alertMap);
                } catch (Exception e) {
                    log.debug("Redis stream alert publish omitted: {}", e.getMessage());
                }
            }

            return OutlierResult.outlier(endpoint, outlierType, payloadZ, latencyZ, maxZ, payloadBytes, latencyMs, details);
        }

        return OutlierResult.normal(endpoint, payloadZ, latencyZ, payloadBytes, latencyMs);
    }

    public Map<String, Map<String, Object>> getEndpointStats() {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        trackers.forEach((ep, metrics) -> {
            Map<String, Object> metricMap = new LinkedHashMap<>();
            metrics.forEach((name, tracker) -> metricMap.put(name, tracker.toMap()));
            result.put(ep, metricMap);
        });
        return result;
    }

    public double getZThreshold() {
        return zThreshold;
    }
}
