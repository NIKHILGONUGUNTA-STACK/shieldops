package com.aegis.gateway.workflow;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WorkflowEnforcementFilterTest {

    private WorkflowStateService workflowStateService;
    private WorkflowEnforcementFilter filter;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        workflowStateService = new WorkflowStateService(null);
        objectMapper = new ObjectMapper();
        filter = new WorkflowEnforcementFilter(workflowStateService, objectMapper);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Filter blocks out-of-order transfer with 403 Forbidden")
    void testFilterBlocksOutOfOrderTransfer() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/transfers");
        request.addHeader(WorkflowEnforcementFilter.SESSION_ID_HEADER, "test-attacker-session");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        // Authenticated customer without prior account check
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("user1", "N/A", List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")))
        );

        filter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentType().contains("application/problem+json"));
        String body = response.getContentAsString();
        assertTrue(body.contains("Business Workflow Violation"));
        assertTrue(body.contains("RULE-WF-TRANSFER-01"));

        // Verify downstream filter chain was HALTED
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Filter allows transfer after prerequisite step is recorded")
    void testFilterAllowsValidSequence() throws ServletException, IOException {
        String sessionId = "test-legitimate-session";
        FilterChain filterChain = mock(FilterChain.class);

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("user2", "N/A", List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")))
        );

        // Step 1: Customer requests /api/v1/accounts
        MockHttpServletRequest step1Req = new MockHttpServletRequest("GET", "/api/v1/accounts");
        step1Req.addHeader(WorkflowEnforcementFilter.SESSION_ID_HEADER, sessionId);
        MockHttpServletResponse step1Res = new MockHttpServletResponse();
        filter.doFilter(step1Req, step1Res, filterChain);
        verify(filterChain, times(1)).doFilter(step1Req, step1Res);

        // Step 2: Customer executes transfer
        MockHttpServletRequest step2Req = new MockHttpServletRequest("POST", "/api/v1/transfers");
        step2Req.addHeader(WorkflowEnforcementFilter.SESSION_ID_HEADER, sessionId);
        MockHttpServletResponse step2Res = new MockHttpServletResponse();
        filter.doFilter(step2Req, step2Res, filterChain);

        assertEquals(200, step2Res.getStatus());
        verify(filterChain, times(1)).doFilter(step2Req, step2Res);
    }

    @Test
    @DisplayName("Filter bypasses OPTIONS requests and actuator health checks")
    void testFilterBypassesPublicRoutes() throws ServletException, IOException {
        MockHttpServletRequest optReq = new MockHttpServletRequest("OPTIONS", "/api/v1/transfers");
        MockHttpServletResponse optRes = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(optReq, optRes, filterChain);
        verify(filterChain, times(1)).doFilter(optReq, optRes);

        MockHttpServletRequest healthReq = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse healthRes = new MockHttpServletResponse();
        filter.doFilter(healthReq, healthRes, filterChain);
        verify(filterChain, times(1)).doFilter(healthReq, healthRes);
    }
}
