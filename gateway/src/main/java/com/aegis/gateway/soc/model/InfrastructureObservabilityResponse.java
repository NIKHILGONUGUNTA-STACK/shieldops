package com.aegis.gateway.soc.model;

import java.time.Instant;

public record InfrastructureObservabilityResponse(
    Instant timestamp,
    String gatewayStatus,
    long uptimeSeconds,
    JvmMetrics jvm,
    DatabaseMetrics database,
    RedisMetrics redis,
    TelemetryPipelineMetrics telemetryPipeline
) {
    public record JvmMetrics(
        long heapUsedBytes,
        long heapMaxBytes,
        long heapTotalBytes,
        long heapFreeBytes,
        int activeThreads,
        int peakThreads,
        int daemonThreads,
        double processCpuLoad,
        double systemCpuLoad
    ) {}

    public record DatabaseMetrics(
        String status,
        int activeConnections,
        int idleConnections,
        int totalConnections,
        int maxConnections
    ) {}

    public record RedisMetrics(
        String status,
        String streamKey,
        Long streamLength,
        String pingResponse
    ) {}

    public record TelemetryPipelineMetrics(
        long totalEventsPersisted,
        long eventsLastHour,
        Instant latestEventTimestamp,
        long freshnessSeconds,
        long failureCount
    ) {}
}
