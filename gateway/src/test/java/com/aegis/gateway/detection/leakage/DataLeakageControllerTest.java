package com.aegis.gateway.detection.leakage;

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
@DisplayName("DataLeakageController Integration Tests")
class DataLeakageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("Unauthenticated request to leakage summary returns 401 Unauthorized")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/summary"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    @DisplayName("Customer role request to leakage summary returns 403 Forbidden")
    void customerRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/summary")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @Test
    @DisplayName("Analyst request to leakage summary returns 200 OK with summary metrics")
    void analystCanGetSummary() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/summary")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalLeakageIncidents").isNumber())
            .andExpect(jsonPath("$.confirmedBolaLeaks").isNumber())
            .andExpect(jsonPath("$.deniedBolaAttempts").isNumber())
            .andExpect(jsonPath("$.sensitiveDataExposures").isNumber())
            .andExpect(jsonPath("$.bulkExtractionEvents").isNumber())
            .andExpect(jsonPath("$.multiStageCampaigns").isNumber())
            .andExpect(jsonPath("$.generatedAt").isNotEmpty());
    }

    @Test
    @DisplayName("Analyst request to leakage incidents returns 200 OK with paginated list")
    void analystCanGetIncidents() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/incidents")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").isNumber())
            .andExpect(jsonPath("$.content").isArray());
    }

    @Test
    @DisplayName("Analyst request to leakage rules returns 200 OK with rule metadata")
    void analystCanGetRules() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/rules")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(4))))
            .andExpect(jsonPath("$[*].ruleId", hasItems(
                "RULE-BOLA-CONFIRMED-01",
                "RULE-DATA-LEAK-01",
                "RULE-BULK-EXTRACT-01",
                "RULE-BOLA-02"
            )));
    }

    @Test
    @DisplayName("Analyst request to evaluation benchmark returns 200 OK with comparative metrics")
    void analystCanGetBenchmark() throws Exception {
        mockMvc.perform(get("/api/v1/security/leakage/evaluation/benchmark")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.datasetSize").value(23))
            .andExpect(jsonPath("$.isolatedRules.mode").value("ISOLATED_RULES"))
            .andExpect(jsonPath("$.isolatedRules.precision").isNumber())
            .andExpect(jsonPath("$.contextualCorrelation.mode").value("CONTEXTUAL_CORRELATION"))
            .andExpect(jsonPath("$.contextualCorrelation.precision").value(1.0))
            .andExpect(jsonPath("$.contextualCorrelation.falsePositives").value(0))
            .andExpect(jsonPath("$.robustnessFindings", hasSize(greaterThanOrEqualTo(6))))
            .andExpect(jsonPath("$.generatedAt").isNotEmpty());
    }
}

