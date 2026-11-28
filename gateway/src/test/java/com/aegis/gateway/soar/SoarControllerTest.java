package com.aegis.gateway.soar;

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

import java.time.Duration;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SoarControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private DynamicWafService dynamicWafService;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private SoarTicketingService ticketingService;

    @Autowired
    private AdaptiveChallengeService challengeService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("GET /api/v1/security/soar/waf/rules requires authentication")
    void testWafRulesRequiresAuth() throws Exception {
        mockMvc.perform(get("/api/v1/security/soar/waf/rules"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/security/soar/waf/rules returns active bans for SECURITY_ANALYST")
    void testGetWafRules() throws Exception {
        dynamicWafService.addBan("198.51.100.99", "Automated threat block", "INC-TEST-01", Duration.ofHours(2), "SOAR");

        mockMvc.perform(get("/api/v1/security/soar/waf/rules")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$[?(@.ipOrCidr == '198.51.100.99')].reason", contains("Automated threat block")));
    }

    @Test
    @DisplayName("POST /api/v1/security/soar/waf/ban adds rule for SECURITY_ADMIN")
    void testAddWafBan() throws Exception {
        SoarController.BanRequest banReq = new SoarController.BanRequest(
                "203.0.113.55",
                "DDoS Mitigation",
                "INC-TEST-02",
                12,
                "MANUAL"
        );

        mockMvc.perform(post("/api/v1/security/soar/waf/ban")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(banReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.ipOrCidr", is("203.0.113.55")))
                .andExpect(jsonPath("$.reason", is("DDoS Mitigation")));
    }

    @Test
    @DisplayName("DELETE /api/v1/security/soar/waf/ban/{id} deletes rule for SECURITY_ADMIN")
    void testDeleteWafBan() throws Exception {
        WafBanRule rule = dynamicWafService.addBan("192.0.2.11", "Temporary test ban", "INC-TEST-DEL", Duration.ofHours(1), "SOAR");

        mockMvc.perform(delete("/api/v1/security/soar/waf/ban/" + rule.id())
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
                .andExpect(status().isNoContent());

        mockMvc.perform(delete("/api/v1/security/soar/waf/ban/non-existent-id")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /api/v1/security/soar/waf/export/cloudflare exports Cloudflare schema")
    void testExportCloudflare() throws Exception {
        mockMvc.perform(get("/api/v1/security/soar/waf/export/cloudflare")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is("aegis_threat_null_route")))
                .andExpect(jsonPath("$.kind", is("ip_list")))
                .andExpect(jsonPath("$.items", isA(Iterable.class)));
    }

    @Test
    @DisplayName("GET /api/v1/security/soar/waf/export/aws exports AWS WAF IPSet schema")
    void testExportAws() throws Exception {
        mockMvc.perform(get("/api/v1/security/soar/waf/export/aws")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Name", is("AegisAutonomousIPSet")))
                .andExpect(jsonPath("$.Addresses", isA(Iterable.class)));
    }

    @Test
    @DisplayName("GET /api/v1/security/soar/waf/export/iptables exports iptables script")
    void testExportIptables() throws Exception {
        mockMvc.perform(get("/api/v1/security/soar/waf/export/iptables")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", isA(Iterable.class)));
    }

    @Test
    @DisplayName("POST /api/v1/security/soar/tokens/revoke creates token revocation record")
    void testRevokeToken() throws Exception {
        SoarController.TokenRevokeRequest req = new SoarController.TokenRevokeRequest(
                "jti-controller-test-01",
                "user-threat",
                "Compromised credential",
                24
        );

        mockMvc.perform(post("/api/v1/security/soar/tokens/revoke")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.jti", is("jti-controller-test-01")))
                .andExpect(jsonPath("$.subject", is("user-threat")));
    }

    @Test
    @DisplayName("POST /api/v1/security/soar/tokens/revoke-subject performs subject cutoff")
    void testRevokeSubject() throws Exception {
        SoarController.SubjectRevokeRequest req = new SoarController.SubjectRevokeRequest(
                "user-session-hijack",
                "Suspected account takeover",
                12
        );

        mockMvc.perform(post("/api/v1/security/soar/tokens/revoke-subject")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("SOAR Ticketing flow: create, get, callback")
    void testSoarTicketingFlow() throws Exception {
        SoarController.CreateTicketRequest createReq = new SoarController.CreateTicketRequest(
                "INC-SEC-88",
                "Jira",
                "Critical API Exfiltration",
                "CRITICAL",
                "secops-lead"
        );

        String ticketJson = mockMvc.perform(post("/api/v1/security/soar/tickets")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title", is("Critical API Exfiltration")))
                .andExpect(jsonPath("$.status", is("OPEN")))
                .andReturn().getResponse().getContentAsString();

        SoarTicket createdTicket = objectMapper.readValue(ticketJson, SoarTicket.class);

        mockMvc.perform(get("/api/v1/security/soar/tickets")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));

        // Public webhook callback
        SoarController.WebhookCallbackRequest callbackReq = new SoarController.WebhookCallbackRequest(
                createdTicket.externalTicketId(),
                "IN_PROGRESS",
                "Investigating incident in Jira"
        );

        mockMvc.perform(post("/api/v1/security/soar/tickets/callback")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(callbackReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("IN_PROGRESS")));
    }

    @Test
    @DisplayName("Adaptive Challenge flow: issue, verify, status, metrics")
    void testAdaptiveChallengeFlow() throws Exception {
        SoarController.IssueChallengeRequest issueReq = new SoarController.IssueChallengeRequest(
                "session-challenge-ctrl",
                "High risk anomalous transfer",
                0.88
        );

        String responseBody = mockMvc.perform(post("/api/v1/security/soar/challenge/issue")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(issueReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sessionId", is("session-challenge-ctrl")))
                .andExpect(jsonPath("$.challengeNonce", notNullValue()))
                .andReturn().getResponse().getContentAsString();

        AdaptiveChallengeService.ChallengeSession session = objectMapper.readValue(
                responseBody,
                AdaptiveChallengeService.ChallengeSession.class
        );

        // Verification endpoint
        SoarController.VerifyChallengeRequest verifyReq = new SoarController.VerifyChallengeRequest(
                "session-challenge-ctrl",
                session.challengeNonce()
        );

        mockMvc.perform(post("/api/v1/security/soar/challenge/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(verifyReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified", is(true)))
                .andExpect(jsonPath("$.status", is("CLEARED")));

        // Status endpoint
        mockMvc.perform(get("/api/v1/security/soar/challenge/status/session-challenge-ctrl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cleared", is(true)));

        // Metrics endpoint
        mockMvc.perform(get("/api/v1/security/soar/challenge/metrics")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeChallenges", notNullValue()))
                .andExpect(jsonPath("$.activeClearances", notNullValue()));
    }
}
