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
import java.util.Collection;
import java.util.Map;
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
        String customerId = "";
        String rolesStr = "";

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            userId = jwt.getSubject() != null ? jwt.getSubject() : "authenticated";
            String cid = jwt.getClaimAsString("customerId");
            if (cid != null && !cid.isBlank()) {
                customerId = cid;
            }
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
                rolesStr = roles.stream().map(Object::toString).collect(Collectors.joining(","));
            }
        }

        String httpMethod = request.getMethod();
        String requestPath = request.getRequestURI();

        String attestation = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, customerId, rolesStr, httpMethod, requestPath, internalSecret
        );

        HeaderMapRequestWrapper wrapper;
        if (request instanceof HeaderMapRequestWrapper hmrw) {
            wrapper = hmrw;
        } else {
            wrapper = new HeaderMapRequestWrapper(request);
        }

        wrapper.setHeader(TrustTokenUtils.SIGNATURE_HEADER, attestation);
        wrapper.setHeader(TrustTokenUtils.USER_ID_HEADER, userId);
        wrapper.setHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, customerId);
        wrapper.setHeader(TrustTokenUtils.ROLES_HEADER, rolesStr);

        filterChain.doFilter(wrapper, response);
    }
}
