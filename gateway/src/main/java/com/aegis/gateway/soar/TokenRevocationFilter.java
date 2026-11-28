package com.aegis.gateway.soar;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;

/**
 * Gateway edge filter enforcing active WAF IP bans and distributed cryptographic JWT token revocation.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 35)
public class TokenRevocationFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(TokenRevocationFilter.class);

    private final TokenRevocationService tokenRevocationService;
    private final DynamicWafService dynamicWafService;
    private final ObjectMapper objectMapper;

    @Autowired
    public TokenRevocationFilter(
            TokenRevocationService tokenRevocationService,
            DynamicWafService dynamicWafService,
            ObjectMapper objectMapper) {
        this.tokenRevocationService = tokenRevocationService;
        this.dynamicWafService = dynamicWafService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();

        if ("OPTIONS".equalsIgnoreCase(method)) {
            return true;
        }

        return path.startsWith("/actuator/") ||
               path.startsWith("/ws/") ||
               path.startsWith("/topic/") ||
               path.startsWith("/app/") ||
               path.equals("/healthz") ||
               path.startsWith("/api/v1/security/soar/tickets/callback");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // 1. Dynamic WAF IP Ban check
        String clientIp = extractClientIp(request);
        if (dynamicWafService.isBanned(clientIp)) {
            log.warn("Blocked request from banned IP: {} to {} {}", clientIp, request.getMethod(), request.getRequestURI());
            respondProblemDetail(
                    response,
                    HttpStatus.FORBIDDEN,
                    "Forbidden - IP Banned",
                    "https://aegis.dev/errors/ip-banned",
                    "Client IP address " + clientIp + " has been temporarily banned by Aegis Autonomous SOAR."
            );
            return;
        }

        // 2. Token Revocation check
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String jti = jwt.getId();
            String subject = jwt.getSubject();
            Instant issuedAt = jwt.getIssuedAt();

            if (tokenRevocationService.isRevoked(jti, subject, issuedAt)) {
                log.warn("Blocked revoked JWT: JTI={}, Subject={}, Path={}", jti, subject, request.getRequestURI());
                respondProblemDetail(
                        response,
                        HttpStatus.UNAUTHORIZED,
                        "Token Revoked",
                        "https://aegis.dev/errors/token-revoked",
                        "Access token has been revoked by autonomous security policy."
                );
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private void respondProblemDetail(
            HttpServletResponse response,
            HttpStatus status,
            String title,
            String typeUri,
            String detail) throws IOException {

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        problem.setType(URI.create(typeUri));

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(problem));
    }
}
