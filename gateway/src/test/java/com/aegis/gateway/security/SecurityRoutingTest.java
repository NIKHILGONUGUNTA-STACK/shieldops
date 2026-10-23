package com.aegis.gateway.security;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityRoutingTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    void actuatorHealthIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/actuator/health"))
            .andExpect(status().isOk());
    }

    @Test
    void actuatorPrometheusIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/actuator/prometheus"))
            .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointWithoutTokenReturnsUnauthorizedProblemDetail() throws Exception {
        mockMvc.perform(get("/customers/10000000-0000-4000-8000-000000000001"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    void protectedEndpointWithValidCustomerJwtPassesSecurity() throws Exception {
        mockMvc.perform(get("/customers/10000000-0000-4000-8000-000000000001")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
                    .jwt(j -> j.claim("customerId", "10000000-0000-4000-8000-000000000001"))))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401))
            .andExpect(header().exists("X-Correlation-Id"));
    }

    @Test
    void transfersEndpointAllowsCustomerRoleToPassSecurity() throws Exception {
        mockMvc.perform(post("/transfers")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401))
            .andExpect(result -> {
                // If downstream returned 403, verify it was NOT Spring Security's "Access is denied"
                if (result.getResponse().getStatus() == 403) {
                    assertThat(result.getResponse().getContentAsString()).doesNotContain("Access is denied");
                }
            });
    }

    @Test
    void transfersEndpointRejectsAnalystRoleWithForbidden() throws Exception {
        mockMvc.perform(post("/transfers")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.detail").value("Access is denied"));
    }

    @Test
    void securityEndpointRejectsCustomerRoleWithForbidden() throws Exception {
        mockMvc.perform(get("/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.detail").value("Access is denied"));
    }

    @Test
    void securityEndpointAllowsAnalystRole() throws Exception {
        mockMvc.perform(get("/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(403));
    }
}
