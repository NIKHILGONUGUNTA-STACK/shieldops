package com.aegis.gateway.reconciliation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * Repository for querying telemetry observations within a bounded time window
 * and declared operations from persistent OpenAPI specifications.
 */
@Repository
public class ApiReconciliationRepository {

    private static final Logger log = LoggerFactory.getLogger(ApiReconciliationRepository.class);
    private final JdbcClient jdbcClient;

    public ApiReconciliationRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record RawObservedOperation(
        String httpMethod,
        String endpointRoute,
        long totalRequests,
        Instant firstObserved,
        Instant lastObserved,
        long count2xx,
        long count3xx,
        long count4xx,
        long count5xx,
        long authFailures,
        long anomalyEvents
    ) {}

    public record RawDeclaredOperation(
        UUID operationId,
        UUID specificationId,
        String specificationName,
        String specificationVersion,
        String httpMethod,
        String pathPattern,
        String normalizedRoute,
        String openApiOperationId,
        String serviceBoundary,
        String summary,
        String description,
        String openapiVersion,
        String format,
        String sourceFilename
    ) {}

    /**
     * Aggregates telemetry events within the bounded observation window.
     */
    public List<RawObservedOperation> findObservedOperationsInWindow(Instant windowStart, Instant windowEnd, String httpMethod) {
        StringBuilder sql = new StringBuilder("""
            SELECT
                http_method,
                COALESCE(NULLIF(route_id, ''), request_path) AS endpoint_route,
                COUNT(*) AS total_requests,
                MIN(timestamp) AS first_observed,
                MAX(timestamp) AS last_observed,
                SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS count_2xx,
                SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS count_3xx,
                SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS count_4xx,
                SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS count_5xx,
                SUM(CASE WHEN status_code IN (401, 403) THEN 1 ELSE 0 END) AS auth_failures,
                SUM(CASE WHEN anomaly_flags IS NOT NULL AND anomaly_flags != 'NONE' AND anomaly_flags != '' THEN 1 ELSE 0 END) AS anomaly_events
            FROM security_data.api_events
            WHERE timestamp >= :windowStart AND timestamp <= :windowEnd
            """);

        Map<String, Object> params = new HashMap<>();
        params.put("windowStart", Timestamp.from(windowStart));
        params.put("windowEnd", Timestamp.from(windowEnd));

        if (httpMethod != null && !httpMethod.isBlank()) {
            sql.append(" AND UPPER(http_method) = :httpMethod");
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
            return new RawObservedOperation(
                rs.getString("http_method"),
                rs.getString("endpoint_route"),
                rs.getLong("total_requests"),
                firstTs != null ? firstTs.toInstant() : windowStart,
                lastTs != null ? lastTs.toInstant() : windowEnd,
                rs.getLong("count_2xx"),
                rs.getLong("count_3xx"),
                rs.getLong("count_4xx"),
                rs.getLong("count_5xx"),
                rs.getLong("auth_failures"),
                rs.getLong("anomaly_events")
            );
        }).list();
    }

    /**
     * Retrieves declared operations across all specifications, or restricted to a specific specification.
     */
    public List<RawDeclaredOperation> findDeclaredOperations(UUID specificationId) {
        StringBuilder sql = new StringBuilder("""
            SELECT
                op.id AS operation_id,
                op.specification_id,
                s.name AS specification_name,
                s.version AS specification_version,
                s.openapi_version,
                s.format,
                s.source_filename,
                op.http_method,
                op.path_pattern,
                op.normalized_route,
                op.operation_id AS openapi_op_id,
                op.service_boundary,
                op.summary,
                op.description
            FROM security_data.api_spec_operations op
            JOIN security_data.api_specifications s ON op.specification_id = s.id
            """);

        Map<String, Object> params = new HashMap<>();
        if (specificationId != null) {
            sql.append(" WHERE op.specification_id = :specId");
            params.put("specId", specificationId);
        }

        sql.append(" ORDER BY s.name ASC, op.normalized_route ASC, op.http_method ASC");

        var spec = jdbcClient.sql(sql.toString());
        for (var entry : params.entrySet()) {
            spec = spec.param(entry.getKey(), entry.getValue());
        }

        return spec.query((rs, rowNum) -> new RawDeclaredOperation(
            (UUID) rs.getObject("operation_id"),
            (UUID) rs.getObject("specification_id"),
            rs.getString("specification_name"),
            rs.getString("specification_version"),
            rs.getString("http_method"),
            rs.getString("path_pattern"),
            rs.getString("normalized_route"),
            rs.getString("openapi_op_id"),
            rs.getString("service_boundary"),
            rs.getString("summary"),
            rs.getString("description"),
            rs.getString("openapi_version"),
            rs.getString("format"),
            rs.getString("source_filename")
        )).list();
    }

    /**
     * Resolves specification name for summary provenance.
     */
    public Optional<String> findSpecificationName(UUID specificationId) {
        if (specificationId == null) {
            return Optional.empty();
        }
        return jdbcClient.sql("SELECT name FROM security_data.api_specifications WHERE id = :id")
            .param("id", specificationId)
            .query(String.class)
            .optional();
    }

    /**
     * Finds distinct HTTP status codes observed for a specific route and method in the observation window.
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
     * Finds active or historical security incidents linked to this service boundary or route within the observation window.
     */
    public List<com.aegis.gateway.reconciliation.dto.InvestigationLinkedIncident> findLinkedIncidents(
            String serviceBoundary, String route, Instant windowStart, Instant windowEnd) {
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
            .param("route", route != null ? route : "")
            .query((rs, rowNum) -> {
                Timestamp ts = rs.getTimestamp("first_detected_at");
                return new com.aegis.gateway.reconciliation.dto.InvestigationLinkedIncident(
                    (UUID) rs.getObject("id"),
                    rs.getString("rule_id"),
                    rs.getString("threat_category"),
                    rs.getString("severity"),
                    rs.getString("status"),
                    rs.getString("summary"),
                    ts != null ? ts.toInstant() : windowStart
                );
            }).list();
    }
}

