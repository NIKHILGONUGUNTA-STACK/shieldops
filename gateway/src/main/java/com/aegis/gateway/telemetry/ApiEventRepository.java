package com.aegis.gateway.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.List;

@Repository
public class ApiEventRepository {
    private static final Logger log = LoggerFactory.getLogger(ApiEventRepository.class);
    private final JdbcClient jdbcClient;

    public ApiEventRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Transactional
    public void save(ApiEvent e) {
        try {
            jdbcClient.sql("""
                INSERT INTO security_data.api_events (
                    id, correlation_id, timestamp, source_ip, http_method,
                    request_path, route_id, status_code, latency_ms,
                    auth_subject, auth_roles, customer_id, user_agent,
                    payload_hash, anomaly_flags,
                    resource_type, resource_id, error_code, response_size_bytes, record_count
                ) VALUES (
                    :id, :correlationId, :timestamp, :sourceIp, :httpMethod,
                    :requestPath, :routeId, :statusCode, :latencyMs,
                    :authSubject, :authRoles, :customerId, :userAgent,
                    :payloadHash, :anomalyFlags,
                    :resourceType, :resourceId, :errorCode, :responseSizeBytes, :recordCount
                )
                """)
                .param("id", e.id())
                .param("correlationId", e.correlationId())
                .param("timestamp", Timestamp.from(e.timestamp()))
                .param("sourceIp", e.sourceIp())
                .param("httpMethod", e.httpMethod())
                .param("requestPath", e.requestPath())
                .param("routeId", e.routeId())
                .param("statusCode", e.statusCode())
                .param("latencyMs", e.latencyMs())
                .param("authSubject", e.authSubject())
                .param("authRoles", e.authRoles())
                .param("customerId", e.customerId())
                .param("userAgent", e.userAgent())
                .param("payloadHash", e.payloadHash())
                .param("anomalyFlags", e.anomalyFlags())
                .param("resourceType", e.resourceType())
                .param("resourceId", e.resourceId())
                .param("errorCode", e.errorCode())
                .param("responseSizeBytes", e.responseSizeBytes())
                .param("recordCount", e.recordCount())
                .update();
        } catch (DuplicateKeyException dke) {
            log.debug("Event {} already persisted (duplicate key ignored)", e.id());
        }
    }

    @Transactional
    public void saveAll(List<ApiEvent> events) {
        for (ApiEvent e : events) {
            save(e);
        }
    }

    public long count() {
        return jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_events")
            .query(Long.class)
            .single();
    }

    public SecurityEventPageResponse findEvents(int page, int size, Integer statusCode, String httpMethod) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        java.util.Map<String, Object> params = new java.util.HashMap<>();

        if (statusCode != null) {
            whereClause.append(" AND status_code = :statusCode");
            params.put("statusCode", statusCode);
        }
        if (httpMethod != null && !httpMethod.isBlank()) {
            whereClause.append(" AND http_method = :httpMethod");
            params.put("httpMethod", httpMethod.toUpperCase().trim());
        }

        String countSql = "SELECT COUNT(*) FROM security_data.api_events" + whereClause;
        var countSpec = jdbcClient.sql(countSql);
        for (java.util.Map.Entry<String, Object> entry : params.entrySet()) {
            countSpec = countSpec.param(entry.getKey(), entry.getValue());
        }
        Long total = countSpec.query(Long.class).single();
        long totalElements = (total != null) ? total : 0L;
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);

        String querySql = "SELECT id, correlation_id, timestamp, source_ip, http_method, " +
                          "request_path, route_id, status_code, latency_ms, " +
                          "auth_subject, auth_roles, customer_id, user_agent, " +
                          "payload_hash, anomaly_flags " +
                          "FROM security_data.api_events" + whereClause +
                          " ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset";

        var querySpec = jdbcClient.sql(querySql);
        for (java.util.Map.Entry<String, Object> entry : params.entrySet()) {
            querySpec = querySpec.param(entry.getKey(), entry.getValue());
        }
        querySpec = querySpec.param("limit", boundedSize).param("offset", offset);

        List<SecurityEventResponse> content = querySpec.query((rs, rowNum) -> {
            Object idObj = rs.getObject("id");
            java.util.UUID id = (idObj instanceof java.util.UUID u) ? u : (idObj != null ? java.util.UUID.fromString(idObj.toString()) : null);
            java.sql.Timestamp ts = rs.getTimestamp("timestamp");
            java.time.Instant timestamp = (ts != null) ? ts.toInstant() : java.time.Instant.EPOCH;

            return new SecurityEventResponse(
                id,
                rs.getString("correlation_id"),
                timestamp,
                rs.getString("source_ip"),
                rs.getString("http_method"),
                rs.getString("request_path"),
                rs.getString("route_id"),
                rs.getInt("status_code"),
                rs.getLong("latency_ms"),
                rs.getString("auth_subject"),
                rs.getString("auth_roles"),
                rs.getString("customer_id"),
                rs.getString("user_agent"),
                rs.getString("payload_hash"),
                rs.getString("anomaly_flags")
            );
        }).list();

        return new SecurityEventPageResponse(
            content,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            boundedPage < (totalPages - 1),
            boundedPage > 0
        );
    }
}
