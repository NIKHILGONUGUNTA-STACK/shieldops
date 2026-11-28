package com.aegis.gateway.federation;

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

import java.time.Instant;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class FederationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private FederationSyncService syncService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("GET /api/v1/security/federation/nodes requires authentication")
    void testNodesRequiresAuth() throws Exception {
        mockMvc.perform(get("/api/v1/security/federation/nodes"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/security/federation/nodes returns cluster nodes for SECURITY_ANALYST")
    void testGetNodes() throws Exception {
        mockMvc.perform(get("/api/v1/security/federation/nodes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))))
                .andExpect(jsonPath("$[0].nodeId", notNullValue()))
                .andExpect(jsonPath("$[0].stateMerkleRoot", notNullValue()));
    }

    @Test
    @DisplayName("GET /api/v1/security/federation/consensus returns cluster consensus status")
    void testGetConsensus() throws Exception {
        mockMvc.perform(get("/api/v1/security/federation/consensus")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.globalMerkleRoot", notNullValue()))
                .andExpect(jsonPath("$.totalNodes", greaterThanOrEqualTo(3)));
    }

    @Test
    @DisplayName("POST /api/v1/security/federation/broadcast enforces SECURITY_ADMIN role")
    void testBroadcastRoleEnforcement() throws Exception {
        FederationController.BroadcastPolicyRequest req = new FederationController.BroadcastPolicyRequest(
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "{\"ip\":\"198.51.100.99\"}"
        );

        // SECURITY_ANALYST should be forbidden (403)
        mockMvc.perform(post("/api/v1/security/federation/broadcast")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden());

        // SECURITY_ADMIN should succeed (201)
        mockMvc.perform(post("/api/v1/security/federation/broadcast")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.policyId", startsWith("FED-POL-")))
                .andExpect(jsonPath("$.cryptographicSignature", notNullValue()));
    }

    @Test
    @DisplayName("POST /api/v1/security/federation/sync accepts valid peer payload and rejects forged payload")
    void testPeerSyncEndpoint() throws Exception {
        String payloadJson = "{\"jti\":\"sync-token-123\"}";
        String sig = MerkleStateCalculator.signPayload(payloadJson, "node-eu-central-dr", 200);

        FederatedPolicyPayload valid = new FederatedPolicyPayload(
                "FED-POL-SYNC-01",
                FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                200,
                Map.of("node-eu-central-dr", 200L),
                payloadJson,
                sig,
                Instant.now()
        );

        mockMvc.perform(post("/api/v1/security/federation/sync")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(valid)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("ACCEPTED")));
    }

    @Test
    @DisplayName("POST /api/v1/security/federation/reconcile restores cluster consensus")
    void testReconcileEndpoint() throws Exception {
        mockMvc.perform(post("/api/v1/security/federation/reconcile")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.synchronizedStatus", is(true)))
                .andExpect(jsonPath("$.divergentNodeCount", is(0)));
    }
}
