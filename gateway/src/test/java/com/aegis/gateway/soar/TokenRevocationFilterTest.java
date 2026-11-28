package com.aegis.gateway.soar;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class TokenRevocationFilterTest {

    private DynamicWafService wafService;
    private TokenRevocationService tokenRevocationService;
    private TokenRevocationFilter filter;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        wafService = new DynamicWafService(null);
        tokenRevocationService = new TokenRevocationService(null);
        objectMapper = new ObjectMapper();
        filter = new TokenRevocationFilter(tokenRevocationService, wafService, objectMapper);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Filter blocks banned IP with 403 Forbidden")
    void testFilterBlocksBannedIp() throws ServletException, IOException {
        wafService.addBan("198.51.100.42", "Credential stuffing", "INC-001", Duration.ofHours(1), "SOAR");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/accounts");
        request.setRemoteAddr("198.51.100.42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentType().contains("application/problem+json"));
        assertTrue(response.getContentAsString().contains("IP Banned"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Filter respects X-Forwarded-For header for IP ban")
    void testFilterBlocksXForwardedForBannedIp() throws ServletException, IOException {
        wafService.addBan("203.0.113.99", "BOLA probe", "INC-002", Duration.ofHours(1), "SOAR");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/accounts");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.99, 10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("IP Banned"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Filter blocks revoked JWT token with 401 Unauthorized")
    void testFilterBlocksRevokedJwt() throws ServletException, IOException {
        tokenRevocationService.revokeToken("jti-compromised-123", "user-bad", "Compromised device", Duration.ofHours(1));

        Jwt jwt = new Jwt(
                "token-value",
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                Map.of("jti", "jti-compromised-123", "sub", "user-bad")
        );
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/transfers");
        request.setRemoteAddr("192.168.1.50");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentType().contains("application/problem+json"));
        assertTrue(response.getContentAsString().contains("Token Revoked"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Filter allows legitimate request through filter chain")
    void testFilterAllowsLegitimateRequest() throws ServletException, IOException {
        Jwt jwt = new Jwt(
                "token-value",
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                Map.of("jti", "jti-clean-999", "sub", "user-clean")
        );
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/accounts");
        request.setRemoteAddr("192.168.1.100");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Filter bypasses OPTIONS and ticket webhook callback")
    void testFilterBypassesPublicRoutes() throws ServletException, IOException {
        MockHttpServletRequest optReq = new MockHttpServletRequest("OPTIONS", "/api/v1/accounts");
        MockHttpServletResponse optRes = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(optReq, optRes, filterChain);
        verify(filterChain, times(1)).doFilter(optReq, optRes);

        MockHttpServletRequest callbackReq = new MockHttpServletRequest("POST", "/api/v1/security/soar/tickets/callback");
        MockHttpServletResponse callbackRes = new MockHttpServletResponse();

        filter.doFilter(callbackReq, callbackRes, filterChain);
        verify(filterChain, times(1)).doFilter(callbackReq, callbackRes);
    }
}
