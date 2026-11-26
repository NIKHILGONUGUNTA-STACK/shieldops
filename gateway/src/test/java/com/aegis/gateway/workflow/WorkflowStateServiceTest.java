package com.aegis.gateway.workflow;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class WorkflowStateServiceTest {

    private WorkflowStateService workflowStateService;

    @BeforeEach
    void setUp() {
        // Null redisTemplate forces robust in-memory fallback
        workflowStateService = new WorkflowStateService(null);
    }

    @Test
    @DisplayName("Path normalization correctly collapses IDs into {id}")
    void testPathNormalization() {
        assertEquals("/api/v1/customers/{id}", WorkflowStateService.normalizePath("/api/v1/customers/cust-12345"));
        assertEquals("/api/v1/accounts/{id}", WorkflowStateService.normalizePath("/api/v1/accounts/acc-98765"));
        assertEquals("/api/v1/records/{id}", WorkflowStateService.normalizePath("/api/v1/records/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"));
        assertEquals("/api/v1/accounts", WorkflowStateService.normalizePath("/api/v1/accounts?page=1&size=10"));
        assertEquals("POST /api/v1/transactions", WorkflowStateService.canonicalKey("post", "/api/v1/transactions"));
    }

    @Test
    @DisplayName("Unsatisfied transfer rule blocks request when no prerequisite steps exist")
    void testUnsatisfiedTransferRuleBlocks() {
        String sessionId = "sess-attacker-001";
        WorkflowCheckResult result = workflowStateService.checkCompliance(
            sessionId,
            "POST",
            "/api/v1/transfers",
            List.of("ROLE_CUSTOMER")
        );

        assertFalse(result.allowed());
        assertEquals("RULE-WF-TRANSFER-01", result.ruleId());
        assertTrue(result.missingPrerequisites().contains("GET /api/v1/accounts"));
        assertNotNull(result.reason());
        assertTrue(result.reason().contains("Business workflow violation"));
    }

    @Test
    @DisplayName("Satisfied prerequisite step allows transfer execution")
    void testSatisfiedPrerequisiteAllowsTransfer() {
        String sessionId = "sess-legitimate-002";

        // Step 1: Customer visits /api/v1/accounts
        workflowStateService.recordStep(sessionId, "GET", "/api/v1/accounts");
        Set<String> steps = workflowStateService.getCompletedSteps(sessionId);
        assertTrue(steps.contains("GET /api/v1/accounts"));

        // Step 2: Customer executes transfer
        WorkflowCheckResult result = workflowStateService.checkCompliance(
            sessionId,
            "POST",
            "/api/v1/transfers",
            List.of("ROLE_CUSTOMER")
        );

        assertTrue(result.allowed());
    }

    @Test
    @DisplayName("Security Admin and Analyst roles bypass workflow sequence enforcement")
    void testAdminBypass() {
        String sessionId = "sess-admin-003";

        // Admin calls transfer without having called /accounts
        WorkflowCheckResult result = workflowStateService.checkCompliance(
            sessionId,
            "POST",
            "/api/v1/transfers",
            List.of("ROLE_SECURITY_ADMIN")
        );

        assertTrue(result.allowed());
    }

    @Test
    @DisplayName("Non-target routes are always allowed")
    void testNonTargetRoutesAllowed() {
        String sessionId = "sess-user-004";

        WorkflowCheckResult result = workflowStateService.checkCompliance(
            sessionId,
            "GET",
            "/api/v1/customers/cust-101",
            List.of("ROLE_CUSTOMER")
        );

        assertTrue(result.allowed());
    }

    @Test
    @DisplayName("Session clear resets completed steps")
    void testSessionClear() {
        String sessionId = "sess-reset-005";
        workflowStateService.recordStep(sessionId, "GET", "/api/v1/accounts");
        assertFalse(workflowStateService.getCompletedSteps(sessionId).isEmpty());

        workflowStateService.clearSession(sessionId);
        assertTrue(workflowStateService.getCompletedSteps(sessionId).isEmpty());
    }
}
