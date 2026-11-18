package com.aegis.gateway.soc.service;

import com.aegis.gateway.soc.model.*;
import com.aegis.gateway.soc.model.InfrastructureObservabilityResponse.*;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class SocOperationsService {

    private static final Logger log = LoggerFactory.getLogger(SocOperationsService.class);

    private final JdbcClient jdbcClient;
    private final ApiEventRepository apiEventRepository;
    private final Optional<DataSource> dataSource;
    private final Optional<StringRedisTemplate> redisTemplate;
    private final Optional<MeterRegistry> meterRegistry;
    private final String streamKey;

    public SocOperationsService(
        JdbcClient jdbcClient,
        ApiEventRepository apiEventRepository,
        @Autowired(required = false) DataSource dataSource,
        @Autowired(required = false) StringRedisTemplate redisTemplate,
        @Autowired(required = false) MeterRegistry meterRegistry,
        @Value("${aegis.telemetry.redis-stream:aegis:stream:api-events}") String streamKey
    ) {
        this.jdbcClient = jdbcClient;
        this.apiEventRepository = apiEventRepository;
        this.dataSource = Optional.ofNullable(dataSource);
        this.redisTemplate = Optional.ofNullable(redisTemplate);
        this.meterRegistry = Optional.ofNullable(meterRegistry);
        this.streamKey = streamKey;
    }

    public NetworkIntelligenceResponse getNetworkIntelligence(Integer windowHours, int limit) {
        int window = (windowHours != null && windowHours > 0) ? Math.min(windowHours, 720) : 24;
        int boundedLimit = Math.min(Math.max(1, limit), 200);
        Instant cutoff = Instant.now().minus(window, ChronoUnit.HOURS);

        String sql = """
            SELECT source_ip,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen,
                   COUNT(*) AS total_requests,
                   SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS requests_2xx,
                   SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS requests_4xx,
                   SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS requests_5xx,
                   COUNT(DISTINCT route_id) AS unique_endpoints,
                   SUM(CASE WHEN anomaly_flags <> 'NONE' AND anomaly_flags IS NOT NULL THEN 1 ELSE 0 END) AS suspicious_count,
                   COUNT(DISTINCT tenant_id) AS tenant_count,
                   COUNT(DISTINCT auth_subject) AS identity_count
            FROM security_data.api_events
            WHERE timestamp >= :cutoff
            GROUP BY source_ip
            ORDER BY total_requests DESC
            LIMIT :limit
            """;

        List<ObservedIpRecord> records = jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .param("limit", boundedLimit)
            .query((rs, rowNum) -> {
                String ip = rs.getString("source_ip");
                Timestamp fs = rs.getTimestamp("first_seen");
                Timestamp ls = rs.getTimestamp("last_seen");
                long total = rs.getLong("total_requests");
                long req2xx = rs.getLong("requests_2xx");
                long req4xx = rs.getLong("requests_4xx");
                long req5xx = rs.getLong("requests_5xx");
                long endpoints = rs.getLong("unique_endpoints");
                long suspicious = rs.getLong("suspicious_count");
                long tenants = rs.getLong("tenant_count");
                long identities = rs.getLong("identity_count");

                double errorRate = total > 0 ? (double) (req4xx + req5xx) / total : 0.0;
                String reputation = evaluateIpReputation(ip);

                return new ObservedIpRecord(
                    ip,
                    fs != null ? fs.toInstant() : Instant.EPOCH,
                    ls != null ? ls.toInstant() : Instant.EPOCH,
                    total,
                    req2xx,
                    req4xx,
                    req5xx,
                    Math.round(errorRate * 1000.0) / 1000.0,
                    endpoints,
                    suspicious,
                    tenants,
                    identities,
                    reputation,
                    "LOCAL_EVALUATION"
                );
            }).list();

        long totalObservedIps = records.size();
        return new NetworkIntelligenceResponse(window, totalObservedIps, records);
    }

    public IdentityIntelligenceResponse getIdentityIntelligence(Integer windowHours, int limit) {
        int window = (windowHours != null && windowHours > 0) ? Math.min(windowHours, 720) : 24;
        int boundedLimit = Math.min(Math.max(1, limit), 200);
        Instant cutoff = Instant.now().minus(window, ChronoUnit.HOURS);

        String sql = """
            SELECT auth_subject,
                   MAX(customer_id) AS customer_id,
                   MAX(auth_roles) AS auth_roles,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen,
                   COUNT(*) AS total_requests,
                   SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS requests_2xx,
                   SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS requests_4xx,
                   SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS requests_5xx,
                   COUNT(DISTINCT source_ip) AS unique_ips,
                   COUNT(DISTINCT tenant_id) AS tenant_count,
                   SUM(CASE WHEN anomaly_flags <> 'NONE' AND anomaly_flags IS NOT NULL THEN 1 ELSE 0 END) AS suspicious_count
            FROM security_data.api_events
            WHERE auth_subject IS NOT NULL AND auth_subject <> ''
              AND timestamp >= :cutoff
            GROUP BY auth_subject
            ORDER BY total_requests DESC
            LIMIT :limit
            """;

        List<ObservedIdentityRecord> records = jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .param("limit", boundedLimit)
            .query((rs, rowNum) -> {
                String subject = rs.getString("auth_subject");
                String customerId = rs.getString("customer_id");
                String roles = rs.getString("auth_roles");
                Timestamp fs = rs.getTimestamp("first_seen");
                Timestamp ls = rs.getTimestamp("last_seen");
                long total = rs.getLong("total_requests");
                long req2xx = rs.getLong("requests_2xx");
                long req4xx = rs.getLong("requests_4xx");
                long req5xx = rs.getLong("requests_5xx");
                long ips = rs.getLong("unique_ips");
                long tenants = rs.getLong("tenant_count");
                long suspicious = rs.getLong("suspicious_count");

                String riskCategory;
                double errorRate = total > 0 ? (double) (req4xx + req5xx) / total : 0.0;
                if (suspicious > 5 || errorRate > 0.5) {
                    riskCategory = "HIGH_RISK";
                } else if (suspicious > 0 || errorRate > 0.2) {
                    riskCategory = "ELEVATED";
                } else {
                    riskCategory = "BENIGN";
                }

                return new ObservedIdentityRecord(
                    subject,
                    customerId,
                    roles,
                    fs != null ? fs.toInstant() : Instant.EPOCH,
                    ls != null ? ls.toInstant() : Instant.EPOCH,
                    total,
                    req2xx,
                    req4xx,
                    req5xx,
                    ips,
                    tenants,
                    suspicious,
                    riskCategory
                );
            }).list();

        return new IdentityIntelligenceResponse(window, records.size(), records);
    }

    public TenantActivityResponse getTenantActivity(Integer windowHours, int limit) {
        int window = (windowHours != null && windowHours > 0) ? Math.min(windowHours, 720) : 24;
        int boundedLimit = Math.min(Math.max(1, limit), 200);
        Instant cutoff = Instant.now().minus(window, ChronoUnit.HOURS);

        String sql = """
            SELECT tenant_id,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen,
                   COUNT(*) AS total_requests,
                   SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS requests_2xx,
                   SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS requests_4xx,
                   SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS requests_5xx,
                   COUNT(DISTINCT auth_subject) AS unique_identities,
                   COUNT(DISTINCT source_ip) AS unique_ips
            FROM security_data.api_events
            WHERE tenant_id IS NOT NULL AND tenant_id <> ''
              AND timestamp >= :cutoff
            GROUP BY tenant_id
            ORDER BY total_requests DESC
            LIMIT :limit
            """;

        List<TenantActivityRecord> records = jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .param("limit", boundedLimit)
            .query((rs, rowNum) -> {
                String tenant = rs.getString("tenant_id");
                Timestamp fs = rs.getTimestamp("first_seen");
                Timestamp ls = rs.getTimestamp("last_seen");
                long total = rs.getLong("total_requests");
                long req2xx = rs.getLong("requests_2xx");
                long req4xx = rs.getLong("requests_4xx");
                long req5xx = rs.getLong("requests_5xx");
                long identities = rs.getLong("unique_identities");
                long ips = rs.getLong("unique_ips");

                double errorRate = total > 0 ? (double) (req4xx + req5xx) / total : 0.0;

                return new TenantActivityRecord(
                    tenant,
                    fs != null ? fs.toInstant() : Instant.EPOCH,
                    ls != null ? ls.toInstant() : Instant.EPOCH,
                    total,
                    req2xx,
                    req4xx,
                    req5xx,
                    identities,
                    ips,
                    Math.round(errorRate * 1000.0) / 1000.0
                );
            }).list();

        return new TenantActivityResponse(window, records.size(), records);
    }

    public InfrastructureObservabilityResponse getInfrastructureObservability() {
        Instant now = Instant.now();
        long uptimeSeconds = ManagementFactory.getRuntimeMXBean().getUptime() / 1000;

        // 1. JVM Metrics
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();

        double systemCpu = os.getSystemLoadAverage();
        double processCpu = 0.0;
        if (os instanceof com.sun.management.OperatingSystemMXBean sunOs) {
            processCpu = Math.round(sunOs.getProcessCpuLoad() * 1000.0) / 10.0;
            systemCpu = Math.round(sunOs.getCpuLoad() * 1000.0) / 10.0;
        }

        JvmMetrics jvm = new JvmMetrics(
            mem.getHeapMemoryUsage().getUsed(),
            mem.getHeapMemoryUsage().getMax(),
            mem.getHeapMemoryUsage().getCommitted(),
            mem.getHeapMemoryUsage().getCommitted() - mem.getHeapMemoryUsage().getUsed(),
            threads.getThreadCount(),
            threads.getPeakThreadCount(),
            threads.getDaemonThreadCount(),
            processCpu,
            systemCpu
        );

        // 2. Database Metrics
        DatabaseMetrics dbMetrics = collectDatabaseMetrics();

        // 3. Redis Metrics
        RedisMetrics redisMetrics = collectRedisMetrics();

        // 4. Telemetry Pipeline Metrics
        long totalEvents = apiEventRepository.count();
        long eventsLastHour = apiEventRepository.countEventsSince(now.minus(1, ChronoUnit.HOURS));
        Optional<Instant> latestEvent = apiEventRepository.findLatestEventTimestamp();
        long freshnessSeconds = latestEvent.map(i -> Math.max(0, Duration.between(i, now).toSeconds())).orElse(-1L);

        long failureCount = 0;
        if (meterRegistry.isPresent()) {
            Counter failureCounter = meterRegistry.get().find("aegis.telemetry.failures").counter();
            if (failureCounter != null) {
                failureCount = (long) failureCounter.count();
            }
        }

        TelemetryPipelineMetrics pipelineMetrics = new TelemetryPipelineMetrics(
            totalEvents,
            eventsLastHour,
            latestEvent.orElse(null),
            freshnessSeconds,
            failureCount
        );

        String gatewayStatus = ("CONNECTED".equals(dbMetrics.status())) ? "HEALTHY" : "DEGRADED";

        return new InfrastructureObservabilityResponse(
            now,
            gatewayStatus,
            uptimeSeconds,
            jvm,
            dbMetrics,
            redisMetrics,
            pipelineMetrics
        );
    }

    private DatabaseMetrics collectDatabaseMetrics() {
        if (dataSource.isEmpty()) {
            return new DatabaseMetrics("UNAVAILABLE", 0, 0, 0, 0);
        }

        DataSource ds = dataSource.get();
        String status = "CONNECTED";
        int active = 0, idle = 0, total = 0, max = 10;

        try {
            Integer probe = jdbcClient.sql("SELECT 1").query(Integer.class).single();
            if (probe == null || probe != 1) {
                status = "DEGRADED";
            }
        } catch (Exception e) {
            status = "DISCONNECTED";
        }

        try {
            if (ds.isWrapperFor(HikariDataSource.class)) {
                HikariDataSource hds = ds.unwrap(HikariDataSource.class);
                HikariPoolMXBean poolBean = hds.getHikariPoolMXBean();
                if (poolBean != null) {
                    active = poolBean.getActiveConnections();
                    idle = poolBean.getIdleConnections();
                    total = poolBean.getTotalConnections();
                }
                max = hds.getMaximumPoolSize();
            }
        } catch (Exception ignored) {}

        return new DatabaseMetrics(status, active, idle, total, max);
    }

    private RedisMetrics collectRedisMetrics() {
        if (redisTemplate.isEmpty()) {
            return new RedisMetrics("NOT_CONFIGURED", streamKey, null, null);
        }

        try {
            StringRedisTemplate rt = redisTemplate.get();
            String ping = rt.getConnectionFactory().getConnection().ping();
            Long size = null;
            try {
                size = rt.opsForStream().size(streamKey);
            } catch (Exception streamEx) {
                log.debug("Stream size query skipped: {}", streamEx.getMessage());
            }

            return new RedisMetrics("CONNECTED", streamKey, size, ping);
        } catch (Exception e) {
            return new RedisMetrics("UNAVAILABLE", streamKey, null, e.getMessage());
        }
    }

    private String evaluateIpReputation(String ip) {
        if (ip == null || ip.isBlank()) return "UNKNOWN";
        String trimmed = ip.trim();
        if (trimmed.equals("127.0.0.1") || trimmed.equals("::1") || trimmed.equalsIgnoreCase("localhost")) {
            return "LOCAL_LOOPBACK";
        }
        if (trimmed.startsWith("10.") || trimmed.startsWith("192.168.") || trimmed.startsWith("172.18.") ||
            trimmed.startsWith("172.17.") || trimmed.startsWith("172.16.") || trimmed.startsWith("172.19.")) {
            return "INTERNAL_NETWORK";
        }
        return "OBSERVED_EXTERNAL";
    }
}
