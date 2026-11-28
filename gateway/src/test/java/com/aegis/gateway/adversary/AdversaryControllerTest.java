package com.aegis.gateway.adversary;

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

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdversaryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AdversaryCampaignService campaignService;

    @Autowired
    private PolicySynthesizerService synthesizerService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("GET /api/v1/security/adversary/campaigns requires authentication")
    void testCampaignsRequiresAuth() throws Exception {
        mockMvc.perform(get("/api/v1/security/adversary/campaigns"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/security/adversary/campaigns returns campaigns for SECURITY_ANALYST")
    void testGetCampaigns() throws Exception {
        mockMvc.perform(get("/api/v1/security/adversary/campaigns")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))))
                .andExpect(jsonPath("$[0].id", notNullValue()));
    }

    @Test
    @DisplayName("POST /api/v1/security/adversary/campaigns/run executes campaign for SECURITY_ADMIN")
    void testRunCampaign() throws Exception {
        AdversaryController.RunCampaignRequest runReq = new AdversaryController.RunCampaignRequest(
                "Controller Probing Test",
                "POST /api/v1/transfers",
                AdversaryMutationStrategy.STEP_SKIPPING,
                10
        );

        mockMvc.perform(post("/api/v1/security/adversary/campaigns/run")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(runReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name", is("Controller Probing Test")))
                .andExpect(jsonPath("$.blockedProbes", is(10)))
                .andExpect(jsonPath("$.evasionRate", is(0.0)));
    }

    @Test
    @DisplayName("Synthesizer lifecycle: get candidates, synthesize, shadow evaluate, and promote")
    void testSynthesizerLifecycle() throws Exception {
        // 1. Get Candidates
        mockMvc.perform(get("/api/v1/security/adversary/synthesizer/candidates")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));

        // 2. Synthesize Policy from Campaign
        AdversaryController.SynthesizeRequest synthReq = new AdversaryController.SynthesizeRequest("ADV-CAMP-002");
        String synthResult = mockMvc.perform(post("/api/v1/security/adversary/synthesizer/synthesize")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(synthReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status", is("CANDIDATE")))
                .andReturn().getResponse().getContentAsString();

        CandidatePolicy created = objectMapper.readValue(synthResult, CandidatePolicy.class);

        // 3. Shadow Mode Evaluation
        AdversaryController.ShadowEvaluationRequest evalReq = new AdversaryController.ShadowEvaluationRequest(25);
        mockMvc.perform(post("/api/v1/security/adversary/synthesizer/evaluate/" + created.id())
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(evalReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shadowEvaluationsCount", is(25)))
                .andExpect(jsonPath("$.shadowFpr", is(0.0)))
                .andExpect(jsonPath("$.status", is("SAFE_FOR_PROMOTION")));

        // 4. Promotion to Active Edge
        mockMvc.perform(post("/api/v1/security/adversary/synthesizer/promote/" + created.id())
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("PROMOTED")))
                .andExpect(jsonPath("$.promotedAt", notNullValue()));
    }
}
