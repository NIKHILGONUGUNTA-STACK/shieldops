package com.aegis.gateway.evaluation;

import com.aegis.gateway.evaluation.dto.AblationResponse;
import com.aegis.gateway.evaluation.dto.ExperimentImportRequest;
import com.aegis.gateway.evaluation.dto.RobustnessFindingDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("ResearchEvaluationController Integration Tests")
class ResearchEvaluationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("Unauthenticated request to evaluation benchmark returns 401 Unauthorized")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/evaluation/benchmark"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    @DisplayName("Customer role request to evaluation benchmark returns 403 Forbidden")
    void customerRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/evaluation/benchmark")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @Test
    @DisplayName("Analyst request to evaluation benchmark returns 200 OK with 200-scenario dataset metrics")
    void analystCanGetEvaluationBenchmark() throws Exception {
        mockMvc.perform(get("/api/v1/security/evaluation/benchmark")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.datasetId").value("DS-AEGIS-RESEARCH-V1"))
            .andExpect(jsonPath("$.datasetVersion").value("1.0.0"))
            .andExpect(jsonPath("$.manifestHash").isNotEmpty())
            .andExpect(jsonPath("$.totalScenarios").value(200))
            .andExpect(jsonPath("$.benignCount").value(80))
            .andExpect(jsonPath("$.maliciousCount").value(70))
            .andExpect(jsonPath("$.ambiguousCount").value(30))
            .andExpect(jsonPath("$.incompleteCount").value(20))
            .andExpect(jsonPath("$.isolatedScenarioMetrics.f1Score").isNumber())
            .andExpect(jsonPath("$.contextualScenarioMetrics.f1Score").isNumber())
            .andExpect(jsonPath("$.isolatedEventMetrics.f1Score").isNumber())
            .andExpect(jsonPath("$.contextualEventMetrics.f1Score").isNumber())
            .andExpect(jsonPath("$.ablationResults", hasSize(greaterThanOrEqualTo(1))))
            .andExpect(jsonPath("$.robustnessFindings", hasSize(greaterThanOrEqualTo(1))))
            .andExpect(jsonPath("$.executedAt").isNotEmpty());
    }

    @Test
    @DisplayName("Analyst request to experiments history returns 200 OK")
    void analystCanGetExperiments() throws Exception {
        mockMvc.perform(get("/api/v1/security/evaluation/experiments")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    @DisplayName("Admin role can import persistent experiment run")
    void adminCanImportExperiment() throws Exception {
        ExperimentImportRequest req = new ExperimentImportRequest(
            "DS-AEGIS-RESEARCH-V1",
            "1.0.0",
            "hash-test-1234",
            200,
            80,
            70,
            30,
            20,
            "EXP-TEST-" + System.currentTimeMillis(),
            "Dual-Mode Comparative Evaluation Test",
            Map.of("sample", "data"),
            List.of(
                new AblationResponse("FULL_CONTEXTUAL", 0.7692, 1.0, 0.8696, 0.2308, 0.0),
                new AblationResponse("NO_IDENTITY", 0.7692, 1.0, 0.8696, 0.2308, 0.0),
                new AblationResponse("NO_TENANT", 0.7692, 1.0, 0.8696, 0.2308, 0.0),
                new AblationResponse("NO_OWNERSHIP", 0.7692, 0.7143, 0.7407, 0.1765, -0.1289),
                new AblationResponse("NO_SENSITIVITY", 0.7407, 0.8571, 0.7947, 0.2308, -0.0749),
                new AblationResponse("NO_AUTH_OUTCOME", 0.8140, 1.0, 0.8974, 0.1860, 0.0278),
                new AblationResponse("NO_TEMPORAL", 0.8451, 0.8571, 0.8511, 0.1209, -0.0185),
                new AblationResponse("NO_CAMPAIGN", 0.7692, 1.0, 0.8696, 0.2308, 0.0)
            ),
            List.of(new RobustnessFindingDto("Test Boundary", "Temporal", "Evict old", "Evicted", true, "Sliding Window"))
        );

        mockMvc.perform(post("/api/v1/security/evaluation/import")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("IMPORTED"))
            .andExpect(jsonPath("$.datasetId").value("DS-AEGIS-RESEARCH-V1"));
    }
}
