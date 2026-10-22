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
                    payload_hash, anomaly_flags
                ) VALUES (
                    :id, :correlationId, :timestamp, :sourceIp, :httpMethod,
                    :requestPath, :routeId, :statusCode, :latencyMs,
                    :authSubject, :authRoles, :customerId, :userAgent,
                    :payloadHash, :anomalyFlags
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
}
