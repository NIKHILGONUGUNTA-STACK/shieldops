package com.aegis.gateway.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class InternalTrustAttestationFilter extends OncePerRequestFilter {
    private final String internalSecret;

    public InternalTrustAttestationFilter(@Value("${aegis.security.internal-secret:aegis-internal-trust-secret-key-32chars!}") String internalSecret) {
        this.internalSecret = internalSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String correlationId = request.getHeader(TrustTokenUtils.CORRELATION_ID_HEADER);
        String userId = "anonymous";
        String customerId = null;
        String rolesStr = "";

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            userId = jwt.getSubject();
            customerId = jwt.getClaimAsString("customerId");
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
                rolesStr = roles.stream().map(Object::toString).collect(Collectors.joining(","));
            }
        }

        if ("anonymous".equals(userId)) {
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
                            userId = json.get("sub").asText();
                        }
                        if (json.has("customerId")) {
                            customerId = json.get("customerId").asText();
                        }
                        if (json.has("realm_access") && json.get("realm_access").has("roles")) {
                            List<String> roleList = new ArrayList<>();
                            json.get("realm_access").get("roles").forEach(r -> roleList.add(r.asText()));
                            rolesStr = String.join(",", roleList);
                        }
                    }
                } catch (Exception ignore) {}
            }
        }

        String attestation = TrustTokenUtils.buildAttestationHeader(correlationId, userId, internalSecret);

        HeaderMapRequestWrapper wrapper;
        if (request instanceof HeaderMapRequestWrapper hmrw) {
            wrapper = hmrw;
        } else {
            wrapper = new HeaderMapRequestWrapper(request);
        }

        wrapper.setHeader(TrustTokenUtils.SIGNATURE_HEADER, attestation);
        wrapper.setHeader(TrustTokenUtils.USER_ID_HEADER, userId != null ? userId : "anonymous");
        if (customerId != null && !customerId.isBlank()) {
            wrapper.setHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, customerId);
        }
        if (!rolesStr.isBlank()) {
            wrapper.setHeader(TrustTokenUtils.ROLES_HEADER, rolesStr);
        }

        filterChain.doFilter(wrapper, response);
    }
}
