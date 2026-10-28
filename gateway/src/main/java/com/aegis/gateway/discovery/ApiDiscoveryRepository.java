package com.aegis.gateway.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * Data access repository for passive API endpoint discovery aggregated from wire telemetry.
 * Read-only aggregation over security_data.api_events.
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
     * Retrieves distinct status codes observed per route.
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
}
