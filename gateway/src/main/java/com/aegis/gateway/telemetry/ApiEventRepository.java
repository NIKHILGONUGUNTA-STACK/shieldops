package com.aegis.gateway.telemetry;

import com.aegis.gateway.detection.dto.TimeSeriesBucketResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

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

    public Optional<SecurityEventResponse> findById(UUID id) {
        String sql = """
            SELECT id, correlation_id, timestamp, source_ip, http_method,
                   request_path, route_id, status_code, latency_ms,
                   auth_subject, auth_roles, customer_id, user_agent,
                   payload_hash, anomaly_flags, resource_type, resource_id,
                   error_code, response_size_bytes, record_count
            FROM security_data.api_events
            WHERE id = :id
            """;
        return jdbcClient.sql(sql)
            .param("id", id)
            .query((rs, rowNum) -> mapRowToEventResponse(rs))
            .optional();
    }

    public SecurityEventPageResponse findEvents(int page, int size, Integer statusCode, String httpMethod) {
        return findEvents(page, size, statusCode, httpMethod, null, null, null, null, null, null, null);
    }

    public SecurityEventPageResponse findEvents(
            int page,
            int size,
            Integer statusCode,
            String httpMethod,
            String customerId,
            String sourceIp,
            String anomalyFlags,
            String resourceType,
            Instant from,
            Instant to,
            String correlationId) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new HashMap<>();

        if (statusCode != null) {
            whereClause.append(" AND status_code = :statusCode");
            params.put("statusCode", statusCode);
        }
        if (httpMethod != null && !httpMethod.isBlank()) {
            whereClause.append(" AND http_method = :httpMethod");
            params.put("httpMethod", httpMethod.toUpperCase().trim());
        }
        if (customerId != null && !customerId.isBlank()) {
            whereClause.append(" AND customer_id = :customerId");
            params.put("customerId", customerId.trim());
        }
        if (sourceIp != null && !sourceIp.isBlank()) {
            whereClause.append(" AND source_ip = :sourceIp");
            params.put("sourceIp", sourceIp.trim());
        }
        if (anomalyFlags != null && !anomalyFlags.isBlank()) {
            whereClause.append(" AND anomaly_flags LIKE :anomalyFlags");
            params.put("anomalyFlags", "%" + anomalyFlags.trim() + "%");
        }
        if (resourceType != null && !resourceType.isBlank()) {
            whereClause.append(" AND resource_type = :resourceType");
            params.put("resourceType", resourceType.trim());
        }
        if (from != null) {
            whereClause.append(" AND timestamp >= :fromTimestamp");
            params.put("fromTimestamp", Timestamp.from(from));
        }
        if (to != null) {
            whereClause.append(" AND timestamp <= :toTimestamp");
            params.put("toTimestamp", Timestamp.from(to));
        }
        if (correlationId != null && !correlationId.isBlank()) {
            whereClause.append(" AND correlation_id = :correlationId");
            params.put("correlationId", correlationId.trim());
        }

        String countSql = "SELECT COUNT(*) FROM security_data.api_events" + whereClause;
        var countSpec = jdbcClient.sql(countSql);
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            countSpec = countSpec.param(entry.getKey(), entry.getValue());
        }
        Long total = countSpec.query(Long.class).single();
        long totalElements = (total != null) ? total : 0L;
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);

        String querySql = "SELECT id, correlation_id, timestamp, source_ip, http_method, " +
                          "request_path, route_id, status_code, latency_ms, " +
                          "auth_subject, auth_roles, customer_id, user_agent, " +
                          "payload_hash, anomaly_flags, resource_type, resource_id, " +
                          "error_code, response_size_bytes, record_count " +
                          "FROM security_data.api_events" + whereClause +
                          " ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset";

        var querySpec = jdbcClient.sql(querySql);
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            querySpec = querySpec.param(entry.getKey(), entry.getValue());
        }
        querySpec = querySpec.param("limit", boundedSize).param("offset", offset);

        List<SecurityEventResponse> content = querySpec.query((rs, rowNum) -> mapRowToEventResponse(rs)).list();

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

    public long countEventsSince(Instant cutoff) {
        return jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_events WHERE timestamp >= :cutoff")
            .param("cutoff", Timestamp.from(cutoff))
            .query(Long.class)
            .single();
    }

    public long countAnomaliesSince(Instant cutoff) {
        String sql = """
            SELECT COUNT(*) FROM security_data.api_events
            WHERE timestamp >= :cutoff
              AND anomaly_flags <> 'NONE'
              AND anomaly_flags IS NOT NULL
            """;
        return jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .query(Long.class)
            .single();
    }

    public List<TimeSeriesBucketResponse> findTimeSeriesTrendSince(Instant cutoff) {
        String sql = """
            SELECT date_trunc('hour', timestamp) AS bucket,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN anomaly_flags <> 'NONE' AND anomaly_flags IS NOT NULL THEN 1 ELSE 0 END) AS anomaly_count
            FROM security_data.api_events
            WHERE timestamp >= :cutoff
            GROUP BY date_trunc('hour', timestamp)
            ORDER BY bucket ASC
            """;
        return jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .query((rs, rowNum) -> {
                Timestamp ts = rs.getTimestamp("bucket");
                String bucketIso = (ts != null) ? ts.toInstant().toString() : "";
                long totalCount = rs.getLong("total_count");
                long anomalyCount = rs.getLong("anomaly_count");
                return new TimeSeriesBucketResponse(bucketIso, totalCount, anomalyCount);
            }).list();
    }

    private SecurityEventResponse mapRowToEventResponse(ResultSet rs) throws SQLException {
        Object idObj = rs.getObject("id");
        UUID id = (idObj instanceof UUID u) ? u : (idObj != null ? UUID.fromString(idObj.toString()) : null);
        Timestamp ts = rs.getTimestamp("timestamp");
        Instant timestamp = (ts != null) ? ts.toInstant() : Instant.EPOCH;

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
            rs.getString("anomaly_flags"),
            rs.getString("resource_type"),
            rs.getString("resource_id"),
            rs.getString("error_code"),
            rs.getLong("response_size_bytes"),
            rs.getInt("record_count")
        );
    }
}
