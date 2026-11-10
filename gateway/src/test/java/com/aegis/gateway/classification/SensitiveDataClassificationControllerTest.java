package com.aegis.gateway.classification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("SensitiveDataClassificationController Integration Tests")
class SensitiveDataClassificationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("Unauthenticated request to classification inventory returns 401 Unauthorized")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/classification/inventory"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    @DisplayName("Customer role request to classification inventory returns 403 Forbidden")
    void customerRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/classification/inventory")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @Test
    @DisplayName("Analyst role request to classification inventory returns 200 OK with paginated content")
    void analystRoleReturns200WithInventory() throws Exception {
        mockMvc.perform(get("/api/v1/security/classification/inventory")
                .param("page", "0")
                .param("size", "10")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(10))
            .andExpect(jsonPath("$.totalElements", greaterThan(0)))
            .andExpect(jsonPath("$.content", not(empty())))
            .andExpect(jsonPath("$.content[0].highestSensitivityLevel").exists())
            .andExpect(jsonPath("$.content[0].fieldClassifications").isArray());
    }

    @Test
    @DisplayName("Analyst role request to classification summary returns 200 OK with metrics")
    void analystRoleReturns200WithSummary() throws Exception {
        mockMvc.perform(get("/api/v1/security/classification/summary")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalMonitoredEndpoints", greaterThan(0)))
            .andExpect(jsonPath("$.totalClassifiedFields", greaterThan(0)))
            .andExpect(jsonPath("$.overallCoveragePercentage", greaterThan(0.0)))
            .andExpect(jsonPath("$.countsBySensitivity.CONFIDENTIAL", greaterThan(0)))
            .andExpect(jsonPath("$.serviceWiseCoverage.customer-service").exists());
    }

    @Test
    @DisplayName("Non-existent endpoint details returns 404 Not Found")
    void nonExistentEndpointReturns404() throws Exception {
        mockMvc.perform(get("/api/v1/security/classification/endpoints/ep_non_existent")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.title").value("Endpoint Classification Not Found"));
    }
}

