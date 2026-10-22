package com.aegis.customer.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;
import java.util.regex.Pattern;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InternalTrustFilter extends OncePerRequestFilter {
    public static final String MDC_CORRELATION_ID = "correlationId";
    public static final String MDC_USER_ID = "userId";
    private static final Pattern VALID_CORRELATION_ID = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    private final String internalSecret;
    private final boolean verificationEnabled;
    private final ObjectMapper objectMapper;

    public InternalTrustFilter(
            @Value("${aegis.security.internal-secret:aegis-internal-trust-secret-key-32chars!}") String internalSecret,
            @Value("${aegis.security.trust-verification.enabled:true}") boolean verificationEnabled,
            ObjectMapper objectMapper) {
        this.internalSecret = internalSecret;
        this.verificationEnabled = verificationEnabled;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/actuator") || path.startsWith("/error")) {
            filterChain.doFilter(request, response);
            return;
        }

        String correlationId = request.getHeader(TrustTokenUtils.CORRELATION_ID_HEADER);
        if (correlationId == null || !VALID_CORRELATION_ID.matcher(correlationId.trim()).matches()) {
            correlationId = UUID.randomUUID().toString();
        } else {
            correlationId = correlationId.trim();
        }

        String userId = request.getHeader(TrustTokenUtils.USER_ID_HEADER);
        MDC.put(MDC_CORRELATION_ID, correlationId);
        if (userId != null && !userId.isBlank()) {
            MDC.put(MDC_USER_ID, userId);
        }
        response.setHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);

        try {
            if (verificationEnabled) {
                String signatureHeader = request.getHeader(TrustTokenUtils.SIGNATURE_HEADER);
                boolean valid = TrustTokenUtils.verifyAttestationHeader(signatureHeader, correlationId, userId, internalSecret, 60);
                if (!valid) {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.FORBIDDEN,
                        "Gateway trust attestation missing or invalid"
                    );
                    problem.setTitle("Forbidden");
                    problem.setType(URI.create("https://aegis.dev/errors/gateway-bypass-rejected"));
                    objectMapper.writeValue(response.getOutputStream(), problem);
                    return;
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_CORRELATION_ID);
            MDC.remove(MDC_USER_ID);
        }
    }
}
