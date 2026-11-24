package com.aegis.gateway.integration.webhook;

import com.aegis.gateway.integration.webhook.dto.WebhookDispatchResult;
import com.aegis.gateway.integration.webhook.dto.WebhookSubscriptionCreateRequest;
import com.aegis.gateway.integration.webhook.dto.WebhookTestDispatchRequest;
import com.aegis.gateway.integration.webhook.model.WebhookEventType;
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
class WebhookAdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("Unauthenticated request to webhook admin returns 401")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/admin/webhooks"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("ROLE_SECURITY_ANALYST can list webhook subscriptions")
    void analystCanListSubscriptions() throws Exception {
        mockMvc.perform(get("/api/v1/admin/webhooks")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))))
            .andExpect(jsonPath("$[0].name", notNullValue()));
    }

    @Test
    @DisplayName("ROLE_SECURITY_ADMIN can create and delete a webhook subscription")
    void adminCanCreateAndDeleteSubscription() throws Exception {
        WebhookSubscriptionCreateRequest req = new WebhookSubscriptionCreateRequest(
            "tenant-fintech-us",
            "Discord SOC Bot",
            "https://discord.com/api/webhooks/12345/abcdef",
            "discord_secret_2026",
            List.of(WebhookEventType.INCIDENT_CRITICAL, WebhookEventType.TEST_PING)
        );

        String responseBody = mockMvc.perform(post("/api/v1/admin/webhooks")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").value(startsWith("sub-")))
            .andExpect(jsonPath("$.name").value("Discord SOC Bot"))
            .andReturn().getResponse().getContentAsString();

        String subId = objectMapper.readTree(responseBody).get("id").asText();

        // Delete created subscription
        mockMvc.perform(delete("/api/v1/admin/webhooks/" + subId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Can trigger diagnostic test dispatch")
    void testDispatchEndpoint() throws Exception {
        WebhookTestDispatchRequest req = new WebhookTestDispatchRequest(
            "https://httpbin.org/post",
            "my_test_secret",
            "Automated test ping"
        );

        mockMvc.perform(post("/api/v1/admin/webhooks/test-dispatch")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.targetUrl").value("https://httpbin.org/post"))
            .andExpect(jsonPath("$.timestamp", notNullValue()));
    }
}
