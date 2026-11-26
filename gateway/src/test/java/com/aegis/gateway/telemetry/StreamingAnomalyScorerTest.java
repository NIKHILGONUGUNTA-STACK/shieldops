package com.aegis.gateway.telemetry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StreamingAnomalyScorerTest {

    private StreamingAnomalyScorer scorer;

    @BeforeEach
    void setUp() {
        scorer = new StreamingAnomalyScorer(null, 3.5);
    }

    @Test
    @DisplayName("WelfordTracker computes exact running mean and standard deviation")
    void testWelfordTrackerCalculations() {
        StreamingAnomalyScorer.WelfordTracker tracker = new StreamingAnomalyScorer.WelfordTracker();
        double[] vals = {10.0, 20.0, 30.0, 40.0, 50.0};
        for (double v : vals) {
            tracker.update(v);
        }

        assertEquals(5, tracker.getCount());
        assertEquals(30.0, tracker.getMean(), 0.001);
        assertEquals(250.0, tracker.getVariance(), 0.001);
        assertEquals(Math.sqrt(250.0), tracker.getStdDev(), 0.001);

        double z30 = tracker.computeZScore(30.0);
        assertEquals(0.0, z30, 0.001);

        double zHigh = tracker.computeZScore(30.0 + (3.5 * tracker.getStdDev()));
        assertEquals(3.5, zHigh, 0.001);
    }

    @Test
    @DisplayName("Streaming evaluation allows normal transactions without flagging")
    void testNormalTrafficNotFlagged() {
        // Establish baseline of 20 requests with mean ~1000 bytes, ~30ms
        for (int i = 0; i < 20; i++) {
            long size = 950 + (i % 10) * 10;
            long lat = 25 + (i % 10);
            StreamingAnomalyScorer.OutlierResult res = scorer.evaluateAndRecord("GET", "/api/v1/customers/cust-100", size, lat);
            assertFalse(res.isOutlier());
        }

        // Normal query within range
        StreamingAnomalyScorer.OutlierResult check = scorer.evaluateAndRecord("GET", "/api/v1/customers/cust-200", 1020, 32);
        assertFalse(check.isOutlier());
        assertNull(check.outlierType());
        assertTrue(check.maxZ() < 3.0);
    }

    @Test
    @DisplayName("Volumetric spike (> 3.5 sigma) triggers VOLUMETRIC_EXFILTRATION")
    void testVolumetricExfiltrationSpike() {
        // Seed baseline
        for (int i = 0; i < 20; i++) {
            scorer.evaluateAndRecord("GET", "/api/v1/accounts/acc-1", 1000 + (i * 5), 30);
        }

        // Spike: 25,000 bytes (massive response size)
        StreamingAnomalyScorer.OutlierResult spike = scorer.evaluateAndRecord("GET", "/api/v1/accounts/acc-2", 25000, 32);

        assertTrue(spike.isOutlier());
        assertEquals("VOLUMETRIC_EXFILTRATION", spike.outlierType());
        assertTrue(spike.payloadZ() > 3.5);
        assertNotNull(spike.details());
        assertTrue(spike.details().contains("spike: payload=25000"));
    }

    @Test
    @DisplayName("Latency degradation spike (> 3.5 sigma) triggers LATENCY_DEGRADATION")
    void testLatencyDegradationSpike() {
        // Seed baseline
        for (int i = 0; i < 20; i++) {
            scorer.evaluateAndRecord("GET", "/api/v1/transactions", 500, 20 + (i % 5));
        }

        // Spike: 2,500 ms latency
        StreamingAnomalyScorer.OutlierResult spike = scorer.evaluateAndRecord("GET", "/api/v1/transactions", 520, 2500);

        assertTrue(spike.isOutlier());
        assertEquals("LATENCY_DEGRADATION", spike.outlierType());
        assertTrue(spike.latencyZ() > 3.5);
    }

    @Test
    @DisplayName("Inspection statistics map returns tracked endpoint metrics")
    void testEndpointStatsMap() {
        scorer.evaluateAndRecord("POST", "/api/v1/transfers", 200, 50);
        Map<String, Map<String, Object>> stats = scorer.getEndpointStats();

        assertTrue(stats.containsKey("POST /api/v1/transfers"));
        Map<String, Object> epStats = stats.get("POST /api/v1/transfers");
        assertTrue(epStats.containsKey("payload_bytes"));
        assertTrue(epStats.containsKey("latency_ms"));
    }
}
