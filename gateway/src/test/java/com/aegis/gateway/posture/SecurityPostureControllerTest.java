package com.aegis.gateway.posture;

import com.aegis.gateway.discovery.RouteNormalizer;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityPostureControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiEventRepository apiEventRepository;

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
        mockMvc.perform(get("/api/v1/security/posture"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    @DisplayName("Role CUSTOMER lacks authority and returns 403 Forbidden")
    void customerLacksRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/posture")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @Test
    @DisplayName("Analyst can query paginated posture assessments")
    void analystCanQueryPosturePage() throws Exception {
        insertEvent("GET", "/api/v1/customers/{customerId}", "customer-service", 200);
        insertEvent("GET", "/api/v1/customers/{customerId}", "customer-service", 200);

        mockMvc.perform(get("/api/v1/security/posture")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(greaterThanOrEqualTo(1))))
            .andExpect(jsonPath("$.content[0].httpMethod").value("GET"))
            .andExpect(jsonPath("$.content[0].normalizedRoute").value("/api/v1/customers/{customerId}"))
            .andExpect(jsonPath("$.content[0].confirmedVulnerability").value(false))
            .andExpect(jsonPath("$.content[0].dimensions.EXPOSURE").exists())
            .andExpect(jsonPath("$.content[0].dimensions.AUTHENTICATION").exists())
            .andExpect(jsonPath("$.content[0].dimensions.AUTHORIZATION").exists())
            .andExpect(jsonPath("$.content[0].dimensions.DATA_SENSITIVITY").exists())
            .andExpect(jsonPath("$.content[0].dimensions.BEHAVIORAL").exists())
            .andExpect(jsonPath("$.content[0].dimensions.SPECIFICATION").exists())
            .andExpect(jsonPath("$.summary.totalAssessedEndpoints").value(greaterThanOrEqualTo(1)));
    }

    @Test
    @DisplayName("Analyst can query posture summary endpoint")
    void analystCanQueryPostureSummary() throws Exception {
        insertEvent("POST", "/api/v1/transfers", "transaction-service", 200);

        mockMvc.perform(get("/api/v1/security/posture/summary")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalAssessedEndpoints").value(greaterThanOrEqualTo(1)))
            .andExpect(jsonPath("$.assessmentRuleVersion").value("v1.0.0"))
            .andExpect(jsonPath("$.distributionByService.transaction-service").value(1));
    }

    @Test
    @DisplayName("Analyst can retrieve individual endpoint posture by deterministic ID")
    void analystCanRetrieveIndividualEndpointPosture() throws Exception {
        insertEvent("GET", "/api/v1/accounts/{accountId}", "account-service", 200);

        // Derive deterministic endpoint ID: sha256("GET:/api/v1/accounts/{accountId}").substring(0, 16)
        String endpointId = RouteNormalizer.generateEndpointId("GET", "/api/v1/accounts/{accountId}");

        mockMvc.perform(get("/api/v1/security/posture/" + endpointId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.endpointId").value(endpointId))
            .andExpect(jsonPath("$.httpMethod").value("GET"))
            .andExpect(jsonPath("$.normalizedRoute").value("/api/v1/accounts/{accountId}"))
            .andExpect(jsonPath("$.confirmedVulnerability").value(false))
            .andExpect(jsonPath("$.dimensions.DATA_SENSITIVITY.status").value("UNKNOWN"));
    }

    @Test
    @DisplayName("Unknown endpoint ID returns 404 ProblemDetail")
    void unknownEndpointReturns404() throws Exception {
        mockMvc.perform(get("/api/v1/security/posture/nonexistent-id-999")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.title").value("Endpoint Not Found"));
    }

    @Test
    @DisplayName("Invalid windowHours parameter returns 400 ProblemDetail")
    void invalidWindowHoursReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/security/posture?windowHours=999")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid Parameter"))
            .andExpect(jsonPath("$.detail").value(containsString("windowHours must be between 1 and 720")));
    }

    @Test
    @DisplayName("Invalid posture filter parameter returns 400 ProblemDetail")
    void invalidPostureFilterReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/security/posture?posture=INVALID_POSTURE")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid Parameter"))
            .andExpect(jsonPath("$.detail").value(containsString("Invalid posture category filter")));
    }

    @Test
    @DisplayName("Invalid dimension filter parameter returns 400 ProblemDetail")
    void invalidDimensionFilterReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/security/posture?dimension=UNKNOWN_DIMENSION")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid Parameter"))
            .andExpect(jsonPath("$.detail").value(containsString("Invalid dimension filter")));
    }

    private void insertEvent(String method, String routeTemplate, String service, int statusCode) {
        String uri = routeTemplate.replace("{customerId}", "cust-123").replace("{accountId}", "acc-456");
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(),
            "cid-" + UUID.randomUUID(),
            Instant.now(),
            "192.168.1.100",
            method,
            uri,
            routeTemplate,
            statusCode,
            42L,
            "analyst",
            "ROLE_SECURITY_ANALYST",
            "cust-1",
            "curl/8.0",
            "hash",
            "NONE"
        );
        apiEventRepository.save(event);
    }
}
