package com.aegis.gateway.telemetry;

import com.aegis.gateway.security.CorrelationFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.connection.stream.Record;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 50)
public class TelemetryFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(TelemetryFilter.class);

    private final StringRedisTemplate redisTemplate;
    private final ApiEventRepository repository;
    private final String streamKey;

    public TelemetryFilter(
            StringRedisTemplate redisTemplate,
            ApiEventRepository repository,
            @Value("${aegis.telemetry.redis-stream:aegis:stream:api-events}") String streamKey) {
        this.redisTemplate = redisTemplate;
        this.repository = repository;
        this.streamKey = streamKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/actuator/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();
        ContentCachingRequestWrapper cachingRequest = new ContentCachingRequestWrapper(request);

        try {
            filterChain.doFilter(cachingRequest, response);
        } finally {
            long latencyMs = System.currentTimeMillis() - startTime;
            int statusCode = response.getStatus();
            recordTelemetry(cachingRequest, response, latencyMs, statusCode);
        }
    }

    private void recordTelemetry(ContentCachingRequestWrapper request, HttpServletResponse response, long latencyMs, int statusCode) {
        try {
            String correlationId = request.getHeader(CorrelationFilter.CORRELATION_ID_HEADER);
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = response.getHeader(CorrelationFilter.CORRELATION_ID_HEADER);
            }
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = UUID.randomUUID().toString();
            }

            String sourceIp = request.getHeader("X-Forwarded-For");
            if (sourceIp == null || sourceIp.isBlank()) {
                sourceIp = request.getRemoteAddr();
            } else if (sourceIp.contains(",")) {
                sourceIp = sourceIp.split(",")[0].trim();
            }

            String authSubject = "anonymous";
            String customerId = "";
            String authRoles = "";

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
                authSubject = jwt.getSubject() != null ? jwt.getSubject() : "authenticated";
                customerId = jwt.getClaimAsString("customerId") != null ? jwt.getClaimAsString("customerId") : "";
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
                    authRoles = roles.stream().map(Object::toString).collect(Collectors.joining(","));
                }
            }

            if ("anonymous".equals(authSubject)) {
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    try {
                        String tokenStr = authHeader.substring(7).trim();
                        String[] parts = tokenStr.split("\\.");
                        if (parts.length >= 2) {
                            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
                            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                            com.fasterxml.jackson.databind.JsonNode json = mapper.readTree(decoded);
                            if (json.has("sub")) {
                                authSubject = json.get("sub").asText();
                            }
                            if (json.has("customerId")) {
                                customerId = json.get("customerId").asText();
                            }
                            if (json.has("realm_access") && json.get("realm_access").has("roles")) {
                                List<String> roleList = new ArrayList<>();
                                json.get("realm_access").get("roles").forEach(r -> roleList.add(r.asText()));
                                authRoles = String.join(",", roleList);
                            }
                        }
                    } catch (Exception ignore) {}
                }
            }

            String payloadHash = computePayloadHash(request.getContentAsByteArray());
            String userAgent = request.getHeader("User-Agent");
            if (userAgent != null && userAgent.length() > 255) {
                userAgent = userAgent.substring(0, 255);
            }

            String anomalyFlags = "NONE";
            if (statusCode == 401) {
                anomalyFlags = "UNAUTHENTICATED_ACCESS";
            } else if (statusCode == 403) {
                anomalyFlags = "FORBIDDEN_ATTEMPT";
            } else if (statusCode >= 500) {
                anomalyFlags = "SERVER_ERROR";
            }

            ApiEvent event = new ApiEvent(
                UUID.randomUUID(),
                correlationId,
                Instant.now(),
                sourceIp != null ? sourceIp : "127.0.0.1",
                request.getMethod(),
                request.getRequestURI(),
                request.getRequestURI(),
                statusCode,
                latencyMs,
                authSubject,
                authRoles,
                customerId,
                userAgent != null ? userAgent : "",
                payloadHash,
                anomalyFlags
            );

            publishToRedisOrDatabase(event);
        } catch (Exception e) {
            log.warn("Failed to record telemetry for request: {}", e.getMessage());
        }
    }

    private void publishToRedisOrDatabase(ApiEvent event) {
        Map<String, String> fields = new HashMap<>();
        fields.put("id", event.id().toString());
        fields.put("correlationId", event.correlationId());
        fields.put("timestamp", event.timestamp().toString());
        fields.put("sourceIp", event.sourceIp());
        fields.put("httpMethod", event.httpMethod());
        fields.put("requestPath", event.requestPath());
        fields.put("routeId", event.routeId() != null ? event.routeId() : "");
        fields.put("statusCode", String.valueOf(event.statusCode()));
        fields.put("latencyMs", String.valueOf(event.latencyMs()));
        fields.put("authSubject", event.authSubject() != null ? event.authSubject() : "");
        fields.put("authRoles", event.authRoles() != null ? event.authRoles() : "");
        fields.put("customerId", event.customerId() != null ? event.customerId() : "");
        fields.put("userAgent", event.userAgent() != null ? event.userAgent() : "");
        fields.put("payloadHash", event.payloadHash() != null ? event.payloadHash() : "");
        fields.put("anomalyFlags", event.anomalyFlags() != null ? event.anomalyFlags() : "NONE");

        try {
            redisTemplate.opsForStream().add(Record.of(fields).withStreamKey(streamKey));
        } catch (Exception redisException) {
            log.debug("Redis stream append failed, falling back to direct DB persist: {}", redisException.getMessage());
            try {
                repository.save(event);
            } catch (Exception dbException) {
                log.error("Direct telemetry database persist also failed: {}", dbException.getMessage());
            }
        }
    }

    private String computePayloadHash(byte[] content) {
        if (content == null || content.length == 0) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            return null;
        }
    }
}
