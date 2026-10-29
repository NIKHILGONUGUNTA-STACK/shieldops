package com.aegis.gateway.reconciliation;

import com.aegis.gateway.specs.ApiSpecificationRepository;
import com.aegis.gateway.specs.DeclaredOperationData;
import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityReconciliationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiEventRepository apiEventRepository;

    @Autowired
    private ApiSpecificationRepository specificationRepository;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcClient.sql("DELETE FROM security_data.api_events").update();
        jdbcClient.sql("DELETE FROM security_data.api_spec_operations").update();
        jdbcClient.sql("DELETE FROM security_data.api_specifications").update();
    }

    @Test
    @DisplayName("Unauthenticated request returns 401 Unauthorized ProblemDetail")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Customer role returns 403 Forbidden ProblemDetail")
    void customerRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Analyst role returns 200 OK with empty reconciliation report")
    void analystRoleReturns200() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(0)))
            .andExpect(jsonPath("$.page", is(0)))
            .andExpect(jsonPath("$.totalElements", is(0)))
            .andExpect(jsonPath("$.summary.totalEvaluated", is(0)))
            .andExpect(jsonPath("$.summary.coveragePercentage", is(0.0)));
    }

    @Test
    @DisplayName("Reconciliation identifies MATCHED, OBSERVED_UNDOCUMENTED, and DOCUMENTED_UNOBSERVED")
    void testReconciliationFindings() throws Exception {
        UUID specId = UUID.randomUUID();
        ApiSpecificationResponse spec = new ApiSpecificationResponse(
            specId, "Customer Microservice", "Customer operations", "1.0.0", "3.0.3",
            "customer.json", "hash-recon-01", "JSON", "VALID", Instant.now(), "admin",
            2, 2, "Valid", List.of()
        );

        List<DeclaredOperationData> ops = List.of(
            new DeclaredOperationData("GET", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}", "getCustomer", "Get", null, null, false, "customer-service"),
            new DeclaredOperationData("DELETE", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}", "deleteCustomer", "Delete", null, null, false, "customer-service")
        );
        specificationRepository.save(spec, ops, "{}");

        Instant now = Instant.now();
        // Telemetry:
        // 1. GET /api/v1/customers/123 -> Matches GET /api/v1/customers/{customerId}
        // 2. POST /api/v1/tokens -> Undocumented
        apiEventRepository.save(new ApiEvent(
            UUID.randomUUID(), "cid-1", now.minusSeconds(60), "192.168.1.10", "GET",
            "/api/v1/customers/123", "/api/v1/customers/{customerId}",
            200, 25L, "sub-1", "ROLE_USER", "cust-1", "agent", "hash", "NONE"
        ));
        apiEventRepository.save(new ApiEvent(
            UUID.randomUUID(), "cid-2", now.minusSeconds(30), "192.168.1.10", "POST",
            "/api/v1/tokens", "/api/v1/tokens",
            201, 15L, "sub-1", "ROLE_USER", "cust-1", "agent", "hash", "NONE"
        ));

        mockMvc.perform(get("/api/v1/security/reconciliation")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements", is(3)))
            .andExpect(jsonPath("$.summary.matchedCount", is(1)))
            .andExpect(jsonPath("$.summary.documentedUnobservedCount", is(1)))
            .andExpect(jsonPath("$.summary.observedUndocumentedCount", is(1)))
            .andExpect(jsonPath("$.summary.coveragePercentage", is(50.0)))
            .andExpect(jsonPath("$.content[?(@.category == 'MATCHED')].httpMethod", contains("GET")))
            .andExpect(jsonPath("$.content[?(@.category == 'MATCHED')].totalRequests", contains(1)))
            .andExpect(jsonPath("$.content[?(@.category == 'DOCUMENTED_UNOBSERVED')].httpMethod", contains("DELETE")))
            .andExpect(jsonPath("$.content[?(@.category == 'OBSERVED_UNDOCUMENTED')].httpMethod", contains("POST")));
    }

    @Test
    @DisplayName("Reconciliation identifies METHOD_MISMATCH when route exists in spec but method differs")
    void testMethodMismatchDetection() throws Exception {
        UUID specId = UUID.randomUUID();
        ApiSpecificationResponse spec = new ApiSpecificationResponse(
            specId, "Account API", "Account operations", "1.0.0", "3.0.0",
            "account.json", "hash-recon-02", "JSON", "VALID", Instant.now(), "admin",
            1, 1, "Valid", List.of()
        );
        List<DeclaredOperationData> ops = List.of(
            new DeclaredOperationData("GET", "/api/v1/accounts/{id}", "/api/v1/accounts/{accountId}", "getAccount", "Get", null, null, false, "account-service")
        );
        specificationRepository.save(spec, ops, "{}");

        // Telemetry observes PATCH on /api/v1/accounts/acc-1
        apiEventRepository.save(new ApiEvent(
            UUID.randomUUID(), "cid-3", Instant.now().minusSeconds(10), "10.0.0.1", "PATCH",
            "/api/v1/accounts/acc-1", "/api/v1/accounts/{accountId}",
            405, 10L, "u-1", "ROLE_USER", "cust-1", "curl", "hash", "NONE"
        ));

        mockMvc.perform(get("/api/v1/security/reconciliation")
                .param("category", "METHOD_MISMATCH")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(1)))
            .andExpect(jsonPath("$.content[0].category", is("METHOD_MISMATCH")))
            .andExpect(jsonPath("$.content[0].httpMethod", is("PATCH")))
            .andExpect(jsonPath("$.content[0].normalizedRoute", is("/api/v1/accounts/{accountId}")))
            .andExpect(jsonPath("$.content[0].declaredMethodsForRoute", contains("GET")));
    }

    @Test
    @DisplayName("Invalid windowHours parameter returns 400 ProblemDetail")
    void invalidWindowHoursReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation")
                .param("windowHours", "9999")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE))
            .andExpect(jsonPath("$.title", is("Bad Request")))
            .andExpect(jsonPath("$.detail", containsString("windowHours must be between")));
    }

    @Test
    @DisplayName("Invalid category parameter returns 400 ProblemDetail")
    void invalidCategoryReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation")
                .param("category", "NON_EXISTENT_CATEGORY")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE))
            .andExpect(jsonPath("$.title", is("Bad Request")))
            .andExpect(jsonPath("$.detail", containsString("Invalid reconciliation category")));
    }

    @Test
    @DisplayName("Summary endpoint returns 200 with summary metrics")
    void summaryEndpointReturns200() throws Exception {
        mockMvc.perform(get("/api/v1/security/reconciliation/summary")
                .param("windowHours", "48")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.windowHours", is(48)))
            .andExpect(jsonPath("$.totalEvaluated", is(0)))
            .andExpect(jsonPath("$.coveragePercentage", is(0.0)));
    }
}
