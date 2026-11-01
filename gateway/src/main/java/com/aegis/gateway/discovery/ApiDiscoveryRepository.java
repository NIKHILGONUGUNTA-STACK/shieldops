package com.aegis.gateway.discovery;

import com.aegis.gateway.discovery.dto.EndpointLinkedIncident;
import com.aegis.gateway.discovery.dto.EndpointSecurityEvent;
import com.aegis.gateway.discovery.dto.EndpointSpecMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * Data access repository for passive API endpoint discovery, observation history,
 * and security event correlation aggregated from wire telemetry.
 * Read-only aggregation over security_data.api_events and cross-table governance joins.
 */
@Repository
public class ApiDiscoveryRepository {

    private static final Logger log = LoggerFactory.getLogger(ApiDiscoveryRepository.class);
    private final JdbcClient jdbcClient;

    public ApiDiscoveryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record RawEndpointAggregate(
        String httpMethod,
        String endpointRoute,
        long totalRequests,
        Instant firstObserved,
        Instant lastObserved,
        Double avgLatency,
        long count2xx,
        long count3xx,
        long count4xx,
        long count5xx
    ) {}

    public record RouteStatusCode(
        String httpMethod,
        String endpointRoute,
        int statusCode
    ) {}

    public record RawObservationBucket(
        Instant bucketTime,
        long requestCount,
        long count2xx,
        long count3xx,
        long count4xx,
        long count5xx,
        Double avgLatency,
        Long minLatency,
        Long maxLatency
    ) {}

    public record SecurityCounts(
        long authFailures,
        long anomalyEvents
    ) {}

    /**
     * Aggregates API telemetry events grouped by HTTP method and route template.
     */
    public List<RawEndpointAggregate> findObservedEndpointAggregates(String httpMethod) {
        StringBuilder sql = new StringBuilder("""
            SELECT
                http_method,
                COALESCE(NULLIF(route_id, ''), request_path) AS endpoint_route,
                COUNT(*) AS total_requests,
                MIN(timestamp) AS first_observed,
                MAX(timestamp) AS last_observed,
                AVG(latency_ms) AS avg_latency,
                SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS count_2xx,
                SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS count_3xx,
                SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS count_4xx,
                SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS count_5xx
            FROM security_data.api_events
            """);

        Map<String, Object> params = new HashMap<>();
        if (httpMethod != null && !httpMethod.isBlank()) {
            sql.append(" WHERE UPPER(http_method) = :httpMethod");
            params.put("httpMethod", httpMethod.toUpperCase().trim());
        }

        sql.append(" GROUP BY http_method, COALESCE(NULLIF(route_id, ''), request_path)");
        sql.append(" ORDER BY MAX(timestamp) DESC");

        var spec = jdbcClient.sql(sql.toString());
        for (var entry : params.entrySet()) {
            spec = spec.param(entry.getKey(), entry.getValue());
        }

        return spec.query((rs, rowNum) -> {
            Timestamp firstTs = rs.getTimestamp("first_observed");
            Timestamp lastTs = rs.getTimestamp("last_observed");
            return new RawEndpointAggregate(
                rs.getString("http_method"),
                rs.getString("endpoint_route"),
                rs.getLong("total_requests"),
                firstTs != null ? firstTs.toInstant() : Instant.EPOCH,
                lastTs != null ? lastTs.toInstant() : Instant.EPOCH,
                rs.getDouble("avg_latency"),
                rs.getLong("count_2xx"),
                rs.getLong("count_3xx"),
                rs.getLong("count_4xx"),
                rs.getLong("count_5xx")
            );
        }).list();
    }

    /**
     * Retrieves distinct status codes observed per route across all history.
     */
    public List<RouteStatusCode> findDistinctStatusCodes() {
        String sql = """
            SELECT DISTINCT
                http_method,
                COALESCE(NULLIF(route_id, ''), request_path) AS endpoint_route,
                status_code
            FROM security_data.api_events
            """;

        return jdbcClient.sql(sql)
            .query((rs, rowNum) -> new RouteStatusCode(
                rs.getString("http_method"),
                rs.getString("endpoint_route"),
                rs.getInt("status_code")
            ))
            .list();
    }

    /**
     * Retrieves distinct status codes observed for a specific route and method within a window.
     */
    public List<Integer> findDistinctStatusCodesForRoute(String httpMethod, String endpointRoute, Instant windowStart, Instant windowEnd) {
        String sql = """
            SELECT DISTINCT status_code
            FROM security_data.api_events
            WHERE timestamp >= :windowStart AND timestamp <= :windowEnd
              AND UPPER(http_method) = :httpMethod
              AND (route_id = :route OR request_path = :route OR COALESCE(NULLIF(route_id, ''), request_path) = :route)
            ORDER BY status_code ASC
            """;

        return jdbcClient.sql(sql)
            .param("windowStart", Timestamp.from(windowStart))
            .param("windowEnd", Timestamp.from(windowEnd))
            .param("httpMethod", httpMethod.toUpperCase().trim())
            .param("route", endpointRoute)
            .query(Integer.class)
            .list();
    }

    /**
     * Counts authorization failures and anomaly event flags for an endpoint within a window.
     */
    public SecurityCounts findSecurityCountsForEndpoint(String httpMethod, String endpointRoute, Instant windowStart, Instant windowEnd) {
        String sql = """
            SELECT
                SUM(CASE WHEN status_code IN (401, 403) THEN 1 ELSE 0 END) AS auth_failures,
                SUM(CASE WHEN anomaly_flags IS NOT NULL AND anomaly_flags <> 'NONE' THEN 1 ELSE 0 END) AS anomaly_events
            FROM security_data.api_events
            WHERE timestamp >= :windowStart AND timestamp <= :windowEnd
              AND UPPER(http_method) = :httpMethod
              AND (route_id = :route OR request_path = :route OR COALESCE(NULLIF(route_id, ''), request_path) = :route)
            """;

        return jdbcClient.sql(sql)
            .param("windowStart", Timestamp.from(windowStart))
            .param("windowEnd", Timestamp.from(windowEnd))
            .param("httpMethod", httpMethod.toUpperCase().trim())
            .param("route", endpointRoute)
            .query((rs, rowNum) -> new SecurityCounts(
                rs.getLong("auth_failures"),
                rs.getLong("anomaly_events")
            ))
            .optional()
            .orElse(new SecurityCounts(0, 0));
    }

    /**
     * Finds declared OpenAPI operation metadata matching an observed endpoint.
     */
    public Optional<EndpointSpecMetadata> findDeclaredOperationForEndpoint(String httpMethod, String normalizedRoute) {
        String sql = """
            SELECT
                s.id AS specification_id,
                s.name AS specification_name,
                s.version AS specification_version,
                COALESCE(s.revision_number, 1) AS revision_number,
                op.operation_id,
                op.summary,
                op.description,
                op.tags,
                op.deprecated
            FROM security_data.api_spec_operations op
            JOIN security_data.api_specifications s ON op.specification_id = s.id
            WHERE UPPER(op.http_method) = :httpMethod
              AND op.normalized_route = :normalizedRoute
            ORDER BY s.imported_at DESC
            LIMIT 1
            """;

        return jdbcClient.sql(sql)
            .param("httpMethod", httpMethod.toUpperCase().trim())
            .param("normalizedRoute", normalizedRoute)
            .query((rs, rowNum) -> new EndpointSpecMetadata(
                (UUID) rs.getObject("specification_id"),
                rs.getString("specification_name"),
                rs.getString("specification_version"),
                rs.getInt("revision_number"),
                rs.getString("operation_id"),
                rs.getString("summary"),
                rs.getString("description"),
                rs.getString("tags"),
                rs.getBoolean("deprecated")
            ))
            .optional();
    }

    /**
     * Executes server-side time-bucketed observation analytics for an endpoint.
     */
    public List<RawObservationBucket> findRawObservationBuckets(
            String httpMethod,
            String endpointRoute,
            Instant windowStart,
            Instant windowEnd,
            String truncInterval) {

        String safeInterval = "day".equalsIgnoreCase(truncInterval) ? "day" : "hour";
        String sql = String.format("""
            SELECT
                date_trunc('%s', timestamp) AS bucket_time,
                COUNT(*) AS request_count,
                SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS count_2xx,
                SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS count_3xx,
                SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS count_4xx,
                SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS count_5xx,
                AVG(latency_ms) AS avg_latency,
                MIN(latency_ms) AS min_latency,
                MAX(latency_ms) AS max_latency
            FROM security_data.api_events
            WHERE timestamp >= :windowStart AND timestamp <= :windowEnd
              AND UPPER(http_method) = :httpMethod
              AND (route_id = :route OR request_path = :route OR COALESCE(NULLIF(route_id, ''), request_path) = :route)
            GROUP BY date_trunc('%s', timestamp)
            ORDER BY bucket_time ASC
            """, safeInterval, safeInterval);

        return jdbcClient.sql(sql)
            .param("windowStart", Timestamp.from(windowStart))
            .param("windowEnd", Timestamp.from(windowEnd))
            .param("httpMethod", httpMethod.toUpperCase().trim())
            .param("route", endpointRoute)
            .query((rs, rowNum) -> {
                Timestamp ts = rs.getTimestamp("bucket_time");
                long count = rs.getLong("request_count");
                Double avgLat = count > 0 ? rs.getDouble("avg_latency") : null;
                Long minLat = count > 0 ? rs.getLong("min_latency") : null;
                Long maxLat = count > 0 ? rs.getLong("max_latency") : null;
                return new RawObservationBucket(
                    ts != null ? ts.toInstant() : windowStart,
                    count,
                    rs.getLong("count_2xx"),
                    rs.getLong("count_3xx"),
                    rs.getLong("count_4xx"),
                    rs.getLong("count_5xx"),
                    avgLat,
                    minLat,
                    maxLat
                );
            })
            .list();
    }

    /**
     * Finds recent security events (401/403 auth failures or anomaly flags) for an endpoint.
     */
    public List<EndpointSecurityEvent> findSecurityEventsForEndpoint(
            String httpMethod,
            String endpointRoute,
            Instant windowStart,
            Instant windowEnd,
            int limit) {

        String sql = """
            SELECT id, timestamp, source_ip, status_code, latency_ms, anomaly_flags, auth_subject
            FROM security_data.api_events
            WHERE timestamp >= :windowStart AND timestamp <= :windowEnd
              AND UPPER(http_method) = :httpMethod
              AND (route_id = :route OR request_path = :route OR COALESCE(NULLIF(route_id, ''), request_path) = :route)
              AND (status_code IN (401, 403) OR (anomaly_flags IS NOT NULL AND anomaly_flags <> 'NONE'))
            ORDER BY timestamp DESC
            LIMIT :limit
            """;

        return jdbcClient.sql(sql)
            .param("windowStart", Timestamp.from(windowStart))
            .param("windowEnd", Timestamp.from(windowEnd))
            .param("httpMethod", httpMethod.toUpperCase().trim())
            .param("route", endpointRoute)
            .param("limit", Math.max(1, Math.min(limit, 100)))
            .query((rs, rowNum) -> {
                Timestamp ts = rs.getTimestamp("timestamp");
                return new EndpointSecurityEvent(
                    (UUID) rs.getObject("id"),
                    ts != null ? ts.toInstant() : windowStart,
                    rs.getString("source_ip"),
                    rs.getInt("status_code"),
                    rs.getLong("latency_ms"),
                    rs.getString("anomaly_flags"),
                    rs.getString("auth_subject")
                );
            })
            .list();
    }

    /**
     * Finds security incidents related to this endpoint or service boundary within the window.
     */
    public List<EndpointLinkedIncident> findLinkedIncidentsForEndpoint(
            String serviceBoundary,
            String endpointRoute,
            Instant windowStart,
            Instant windowEnd) {

        String sql = """
            SELECT id, rule_id, threat_category, severity, status, summary, first_detected_at
            FROM security_data.incidents
            WHERE first_detected_at >= :windowStart AND first_detected_at <= :windowEnd
              AND (
                  target_entity_value = :serviceBoundary
                  OR target_entity_value = :route
                  OR summary ILIKE ('%' || :route || '%')
              )
            ORDER BY first_detected_at DESC
            LIMIT 10
            """;

        return jdbcClient.sql(sql)
            .param("windowStart", Timestamp.from(windowStart))
            .param("windowEnd", Timestamp.from(windowEnd))
            .param("serviceBoundary", serviceBoundary != null ? serviceBoundary : "")
            .param("route", endpointRoute != null ? endpointRoute : "")
            .query((rs, rowNum) -> {
                Timestamp ts = rs.getTimestamp("first_detected_at");
                return new EndpointLinkedIncident(
                    (UUID) rs.getObject("id"),
                    rs.getString("rule_id"),
                    rs.getString("threat_category"),
                    rs.getString("severity"),
                    rs.getString("status"),
                    rs.getString("summary"),
                    ts != null ? ts.toInstant() : windowStart
                );
            })
            .list();
    }
}
