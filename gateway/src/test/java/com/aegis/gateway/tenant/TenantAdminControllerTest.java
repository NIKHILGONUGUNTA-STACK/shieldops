package com.aegis.gateway.tenant;

import com.aegis.gateway.tenant.dto.TenantCreateRequest;
import com.aegis.gateway.tenant.dto.TenantQuotaUpdateRequest;
import com.aegis.gateway.tenant.dto.TenantStatusUpdateRequest;
import com.aegis.gateway.tenant.model.TenantStatus;
import com.aegis.gateway.tenant.model.TenantTier;
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
class TenantAdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("Unauthenticated request to tenant admin returns 401")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tenants"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("ROLE_SECURITY_ANALYST can list tenants")
    void analystCanListTenants() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tenants")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(greaterThanOrEqualTo(4))))
            .andExpect(jsonPath("$.content[0].id", notNullValue()));
    }

    @Test
    @DisplayName("Can retrieve specific tenant by ID")
    void getTenantById() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tenants/tenant-fintech-us")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value("tenant-fintech-us"))
            .andExpect(jsonPath("$.tier").value("ENTERPRISE"))
            .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @DisplayName("Non-existent tenant returns 404 ProblemDetail")
    void getNonExistentTenantReturns404() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tenants/non-existent-tenant-999")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.title").value("Tenant Not Found"));
    }

    @Test
    @DisplayName("ROLE_SECURITY_ADMIN can provision a new tenant")
    void adminCanCreateTenant() throws Exception {
        TenantCreateRequest req = new TenantCreateRequest(
            "tenant-paytech-global",
            "PayTech Global Services",
            TenantTier.PROFESSIONAL,
            6000,
            90,
            List.of("10.200.0.0/16"),
            "contact@paytech.internal",
            "https://hooks.paytech.internal/alerts"
        );

        mockMvc.perform(post("/api/v1/admin/tenants")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").value("tenant-paytech-global"))
            .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @DisplayName("ROLE_SECURITY_ADMIN can update tenant quotas and status")
    void adminCanUpdateTenantQuotasAndStatus() throws Exception {
        TenantStatusUpdateRequest statusReq = new TenantStatusUpdateRequest(TenantStatus.ACTIVE, "Compliance certified");
        mockMvc.perform(patch("/api/v1/admin/tenants/tenant-banking-eu/status")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(statusReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ACTIVE"));

        TenantQuotaUpdateRequest quotaReq = new TenantQuotaUpdateRequest(20000, 365, List.of("172.16.0.0/12"));
        mockMvc.perform(put("/api/v1/admin/tenants/tenant-banking-eu/quotas")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(quotaReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.rateLimitRpm").value(20000));
    }

    @Test
    @DisplayName("Can retrieve tenant telemetry and quota usage")
    void getTenantUsage() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tenants/tenant-fintech-us/usage")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.tenantId").value("tenant-fintech-us"))
            .andExpect(jsonPath("$.rateLimitRpm").value(10000))
            .andExpect(jsonPath("$.rateLimitUtilizationPercent", notNullValue()));
    }
}
