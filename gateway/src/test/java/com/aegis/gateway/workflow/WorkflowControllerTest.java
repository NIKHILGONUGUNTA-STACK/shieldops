package com.aegis.gateway.workflow;

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

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class WorkflowControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WorkflowStateService workflowStateService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("GET /api/v1/security/workflow/rules requires authentication")
    void rulesRequiresAuth() throws Exception {
        mockMvc.perform(get("/api/v1/security/workflow/rules"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/security/workflow/rules returns rules for SECURITY_ADMIN")
    void rulesReturnsForAdmin() throws Exception {
        mockMvc.perform(get("/api/v1/security/workflow/rules")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))))
            .andExpect(jsonPath("$[0].id", is("RULE-WF-TRANSFER-01")));
    }

    @Test
    @DisplayName("POST /api/v1/security/workflow/verify evaluates compliance correctly")
    void verifyStepEndpoint() throws Exception {
        WorkflowController.VerifyRequest verifyReq = new WorkflowController.VerifyRequest(
            "test-verify-session",
            "POST",
            "/api/v1/transfers",
            List.of("ROLE_CUSTOMER")
        );

        mockMvc.perform(post("/api/v1/security/workflow/verify")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.allowed", is(false)))
            .andExpect(jsonPath("$.ruleId", is("RULE-WF-TRANSFER-01")));
    }
}
