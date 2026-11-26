package com.aegis.gateway.workflow;

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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Gateway edge filter enforcing deterministic business workflow prerequisites with zero latency penalty.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 45)
public class WorkflowEnforcementFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(WorkflowEnforcementFilter.class);

    public static final String SESSION_ID_HEADER = "X-Session-ID";
    public static final String WORKFLOW_BYPASS_HEADER = "X-Workflow-Bypass";

    private final WorkflowStateService workflowStateService;
    private final ObjectMapper objectMapper;

    @Autowired
    public WorkflowEnforcementFilter(WorkflowStateService workflowStateService, ObjectMapper objectMapper) {
        this.workflowStateService = workflowStateService;
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
               path.startsWith("/error") ||
               path.startsWith("/auth/") ||
               path.startsWith("/api/v1/security/workflow"); // Exclude workflow management controller
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String method = request.getMethod();
        String rawPath = request.getRequestURI();

        String sessionId = resolveSessionId(request);
        Collection<String> roles = resolveRoles(request);

        // Check workflow compliance
        WorkflowCheckResult check = workflowStateService.checkCompliance(sessionId, method, rawPath, roles);

        if (!check.allowed()) {
            log.warn("Workflow Violation Blocked: session '{}' attempted '{}' without prerequisite in {}",
                sessionId, check.targetEndpoint(), check.missingPrerequisites());

            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);

            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.FORBIDDEN,
                check.reason()
            );
            problem.setType(URI.create("https://aegis.dev/errors/workflow-violation"));
            problem.setTitle("Business Workflow Violation");
            problem.setProperty("ruleId", check.ruleId());
            problem.setProperty("targetEndpoint", check.targetEndpoint());
            problem.setProperty("missingPrerequisites", check.missingPrerequisites());
            problem.setProperty("completedSteps", check.completedSteps());

            objectMapper.writeValue(response.getOutputStream(), problem);
            return;
        }

        // If allowed, record the executed step in session history
        workflowStateService.recordStep(sessionId, method, rawPath);

        filterChain.doFilter(request, response);
    }

    private String resolveSessionId(HttpServletRequest request) {
        // 1. Explicit Session ID Header
        String explicitSessionId = request.getHeader(SESSION_ID_HEADER);
        if (explicitSessionId != null && !explicitSessionId.isBlank()) {
            return explicitSessionId.trim();
        }

        // 2. JWT claims if authenticated
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String sid = jwt.getClaimAsString("sid");
            if (sid != null && !sid.isBlank()) {
                return sid;
            }
            String jti = jwt.getClaimAsString("jti");
            if (jti != null && !jti.isBlank()) {
                return jti;
            }
            if (jwt.getSubject() != null && !jwt.getSubject().isBlank()) {
                return jwt.getSubject();
            }
        }

        // 3. Fallback: Hash of Authorization header or Client IP + User-Agent
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && !authHeader.isBlank()) {
            return hashString(authHeader);
        }

        String ip = request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
        String ua = request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "unknown";
        return hashString(ip + "|" + ua);
    }

    private Collection<String> resolveRoles(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return Collections.emptyList();
        }

        Set<String> roles = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        if (auth.getPrincipal() instanceof Jwt jwt) {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> jwtRoles) {
                for (Object r : jwtRoles) {
                    roles.add("ROLE_" + r.toString().toUpperCase());
                    roles.add(r.toString().toUpperCase());
                }
            }
        }

        return roles;
    }

    private static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return "anon-" + hexString;
        } catch (Exception e) {
            return "anon-" + Math.abs(input.hashCode());
        }
    }
}
