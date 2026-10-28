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
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 50)
public class TelemetryFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(TelemetryFilter.class);

    private static final Pattern CUST_PATH_PATTERN = Pattern.compile("^/(api/v1/)?customers/([0-9a-fA-F-]+)(/profile)?");
    private static final Pattern ACCT_PATH_PATTERN = Pattern.compile("^/(api/v1/)?accounts/([0-9a-fA-F-]+|ACCT-[a-zA-Z0-9_-]+)(/balance)?");
    private static final Pattern TX_PATH_PATTERN = Pattern.compile("^/(api/v1/)?transfers/([0-9a-fA-F-]+)");
    private static final Pattern INJECTION_CHECK_PATTERN = Pattern.compile(
        "(?i)(\\b(UNION(\\s+ALL)?\\s+SELECT|SELECT\\s+.+\\s+FROM|INSERT\\s+INTO|DROP\\s+(TABLE|DATABASE)|WAITFOR\\s+DELAY|SLEEP\\(\\d+\\))\\b|'\\s+OR\\s+('1'='1|1=1)|--|\\.\\./|\\.\\.\\\\|%2e%2e|(;|\\|)\\s*(cat|ls|id|whoami|sh|bash)\\b|<\\s*script\\b|javascript\\s*:|onload\\s*=|onerror\\s*=)"
    );

    private final StringRedisTemplate redisTemplate;
    private final ApiEventRepository repository;
    private final String streamKey;
    private io.micrometer.core.instrument.MeterRegistry meterRegistry;

    public TelemetryFilter(
            StringRedisTemplate redisTemplate,
            ApiEventRepository repository,
            @Value("${aegis.telemetry.redis-stream:aegis:stream:api-events}") String streamKey) {
        this.redisTemplate = redisTemplate;
        this.repository = repository;
        this.streamKey = streamKey;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMeterRegistry(io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/actuator")) {
            filterChain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();
        ContentCachingRequestWrapper cachingRequest = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper cachingResponse = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(cachingRequest, cachingResponse);
        } finally {
            long latencyMs = System.currentTimeMillis() - startTime;
            int statusCode = cachingResponse.getStatus();
            recordTelemetry(cachingRequest, cachingResponse, latencyMs, statusCode);
            cachingResponse.copyBodyToResponse();
        }
    }

    private void recordTelemetry(
            ContentCachingRequestWrapper request,
            ContentCachingResponseWrapper response,
            long latencyMs,
            int statusCode) {
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

            // Fallback: If SecurityContext was cleared on filter exit, parse Authorization Bearer header
            if (customerId.isBlank() || "anonymous".equals(authSubject)) {
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    try {
                        String token = authHeader.substring(7).trim();
                        String[] parts = token.split("\\.");
                        if (parts.length >= 2) {
                            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
                            com.fasterxml.jackson.databind.JsonNode root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(decoded);
                            if (root.has("sub") && "anonymous".equals(authSubject)) {
                                authSubject = root.get("sub").asText();
                            }
                            if (root.has("customerId") && customerId.isBlank()) {
                                customerId = root.get("customerId").asText();
                            }
                            if (root.has("realm_access") && authRoles.isBlank()) {
                                com.fasterxml.jackson.databind.JsonNode rolesNode = root.get("realm_access").get("roles");
                                if (rolesNode != null && rolesNode.isArray()) {
                                    List<String> roles = new ArrayList<>();
                                    rolesNode.forEach(r -> roles.add(r.asText()));
                                    authRoles = String.join(",", roles);
                                }
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }

            String payloadHash = computePayloadHash(request.getContentAsByteArray());
            String userAgent = request.getHeader("User-Agent");
            if (userAgent != null && userAgent.length() > 255) {
                userAgent = userAgent.substring(0, 255);
            }

            String uri = request.getRequestURI();
            String queryString = request.getQueryString();
            boolean hasInjectionPattern = false;
            if (queryString != null && !queryString.isBlank()) {
                String decodedQuery = "";
                try {
                    decodedQuery = java.net.URLDecoder.decode(queryString, StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    decodedQuery = queryString;
                }
                if (INJECTION_CHECK_PATTERN.matcher(decodedQuery).find()) {
                    hasInjectionPattern = true;
                }
            }
            if (!hasInjectionPattern && uri != null) {
                String decodedUri = uri;
                try {
                    decodedUri = java.net.URLDecoder.decode(uri, StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    decodedUri = uri;
                }
                if (INJECTION_CHECK_PATTERN.matcher(decodedUri).find() || INJECTION_CHECK_PATTERN.matcher(uri).find()) {
                    hasInjectionPattern = true;
                }
            }

            String anomalyFlags = "NONE";
            if (hasInjectionPattern) {
                anomalyFlags = "INJECTION_INDICATOR";
            } else if (statusCode == 401) {
                anomalyFlags = "UNAUTHENTICATED_ACCESS";
            } else if (statusCode == 403) {
                anomalyFlags = "FORBIDDEN_ATTEMPT";
            } else if (statusCode == 400) {
                anomalyFlags = "VALIDATION_ERROR";
            } else if (statusCode >= 500) {
                anomalyFlags = "SERVER_ERROR";
            }

            String routeTemplate = normalizeRouteTemplate(uri);

            // Resource context extraction
            String resourceType = null;
            String resourceId = null;

            Matcher custMatcher = CUST_PATH_PATTERN.matcher(uri);
            if (custMatcher.find()) {
                resourceType = custMatcher.group(3) != null ? "CUSTOMER_PROFILE" : "CUSTOMER";
                resourceId = custMatcher.group(2);
            } else {
                Matcher acctMatcher = ACCT_PATH_PATTERN.matcher(uri);
                if (acctMatcher.find()) {
                    resourceType = acctMatcher.group(3) != null ? "ACCOUNT_BALANCE" : "ACCOUNT";
                    resourceId = acctMatcher.group(2);
                } else if (uri.contains("/accounts")) {
                    resourceType = "ACCOUNT_LIST";
                    String qCustId = request.getParameter("customerId");
                    if (qCustId != null && !qCustId.isBlank()) {
                        resourceId = qCustId.trim();
                    }
                } else if (uri.contains("/transfers")) {
                    Matcher txMatcher = TX_PATH_PATTERN.matcher(uri);
                    if (txMatcher.find()) {
                        resourceType = "TRANSFER";
                        resourceId = txMatcher.group(2);
                    } else {
                        resourceType = "TRANSFER_EXECUTION";
                    }
                } else if (uri.contains("/beneficiaries")) {
                    resourceType = "BENEFICIARY";
                }
            }

            // Structured error classification
            String errorCode = null;
            byte[] respBytes = response.getContentAsByteArray();
            long responseSizeBytes = respBytes != null ? respBytes.length : 0L;

            if (hasInjectionPattern) {
                errorCode = "INJECTION_DETECTED";
            } else if (statusCode == 403) {
                String respBody = respBytes != null ? new String(respBytes, StandardCharsets.UTF_8) : "";
                if (respBody.contains("Access to another customer") ||
                    (resourceId != null && !customerId.isBlank() && !customerId.equalsIgnoreCase(resourceId) &&
                     ("CUSTOMER".equals(resourceType) || "CUSTOMER_PROFILE".equals(resourceType) || "ACCOUNT_LIST".equals(resourceType)))) {
                    errorCode = "BOLA_VIOLATION";
                } else if (uri.contains("/security/")) {
                    errorCode = "INSUFFICIENT_ROLE";
                } else {
                    errorCode = "FORBIDDEN";
                }
            } else if (statusCode == 401) {
                errorCode = "UNAUTHENTICATED";
            } else if (statusCode == 400) {
                errorCode = "VALIDATION_ERROR";
            } else if (statusCode == 404) {
                errorCode = "NOT_FOUND";
            } else if (statusCode >= 500) {
                errorCode = "INTERNAL_ERROR";
            }

            int recordCount = 0;
            if (statusCode == 200 && responseSizeBytes > 2 && respBytes != null) {
                if (respBytes[0] == '[' && respBytes[respBytes.length - 1] == ']') {
                    int commas = 0;
                    int depth = 0;
                    for (byte b : respBytes) {
                        if (b == '{') depth++;
                        else if (b == '}') depth--;
                        else if (b == ',' && depth == 0) commas++;
                    }
                    recordCount = (respBytes.length > 2) ? (commas + 1) : 0;
                } else {
                    recordCount = 1;
                }
            }

            ApiEvent event = new ApiEvent(
                UUID.randomUUID(),
                correlationId,
                Instant.now(),
                sourceIp != null ? sourceIp : "127.0.0.1",
                request.getMethod(),
                request.getRequestURI(),
                routeTemplate,
                statusCode,
                latencyMs,
                authSubject,
                authRoles,
                customerId,
                userAgent != null ? userAgent : "",
                payloadHash,
                anomalyFlags,
                resourceType,
                resourceId,
                errorCode,
                responseSizeBytes,
                recordCount
            );

            publishToRedisOrDatabase(event);
        } catch (Exception e) {
            log.warn("Failed to record telemetry for request: {}", e.getMessage());
        }
    }

    private String normalizeRouteTemplate(String uri) {
        return com.aegis.gateway.discovery.RouteNormalizer.normalize(uri);
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
        fields.put("resourceType", event.resourceType() != null ? event.resourceType() : "");
        fields.put("resourceId", event.resourceId() != null ? event.resourceId() : "");
        fields.put("errorCode", event.errorCode() != null ? event.errorCode() : "");
        fields.put("responseSizeBytes", String.valueOf(event.responseSizeBytes()));
        fields.put("recordCount", String.valueOf(event.recordCount()));

        try {
            redisTemplate.opsForStream().add(Record.of(fields).withStreamKey(streamKey));
            if (meterRegistry != null) {
                meterRegistry.counter("aegis.telemetry.events", "route", event.routeId(), "status", String.valueOf(event.statusCode())).increment();
            }
        } catch (Exception redisException) {
            log.debug("Redis stream append failed, falling back to direct DB persist: {}", redisException.getMessage());
            try {
                repository.save(event);
                if (meterRegistry != null) {
                    meterRegistry.counter("aegis.telemetry.events", "route", event.routeId(), "status", String.valueOf(event.statusCode())).increment();
                }
            } catch (Exception dbException) {
                log.error("Direct telemetry database persist also failed: {}", dbException.getMessage());
                if (meterRegistry != null) {
                    meterRegistry.counter("aegis.telemetry.failures", "reason", "db_error").increment();
                }
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
