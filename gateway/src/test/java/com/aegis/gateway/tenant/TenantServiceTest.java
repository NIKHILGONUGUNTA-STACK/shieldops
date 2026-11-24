package com.aegis.gateway.tenant;

import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.aegis.gateway.telemetry.SecurityEventPageResponse;
import com.aegis.gateway.tenant.dto.*;
import com.aegis.gateway.tenant.model.Tenant;
import com.aegis.gateway.tenant.model.TenantStatus;
import com.aegis.gateway.tenant.model.TenantTier;
import com.aegis.gateway.tenant.repository.TenantRepository;
import com.aegis.gateway.tenant.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TenantServiceTest {

    private TenantRepository tenantRepository;
    private ApiEventRepository apiEventRepository;
    private IncidentRepository incidentRepository;
    private TenantService tenantService;

    @BeforeEach
    void setUp() {
        tenantRepository = new TenantRepository();
        apiEventRepository = mock(ApiEventRepository.class);
        incidentRepository = mock(IncidentRepository.class);
        tenantService = new TenantService(tenantRepository, apiEventRepository, incidentRepository);
    }

    @Test
    @DisplayName("Should list all seeded tenants with pagination")
    void testGetTenantsPaged() {
        TenantPageResponse page = tenantService.getTenants(0, 10, null, null, null);
        assertThat(page.totalElements()).isGreaterThanOrEqualTo(4);
        assertThat(page.content()).isNotEmpty();
    }

    @Test
    @DisplayName("Should filter tenants by tier and status")
    void testFilterTenants() {
        TenantPageResponse enterpriseTenants = tenantService.getTenants(0, 10, "ENTERPRISE", "ACTIVE", null);
        assertThat(enterpriseTenants.content()).allMatch(t -> t.tier() == TenantTier.ENTERPRISE && t.status() == TenantStatus.ACTIVE);

        TenantPageResponse searchResult = tenantService.getTenants(0, 10, null, null, "fintech");
        assertThat(searchResult.content()).hasSize(1);
        assertThat(searchResult.content().get(0).id()).isEqualTo("tenant-fintech-us");
    }

    @Test
    @DisplayName("Should retrieve tenant by ID")
    void testGetTenantById() {
        Optional<Tenant> tenant = tenantService.getTenantById("tenant-fintech-us");
        assertThat(tenant).isPresent();
        assertThat(tenant.get().name()).isEqualTo("Fintech US Production");
        assertThat(tenant.get().rateLimitRpm()).isEqualTo(10000);
    }

    @Test
    @DisplayName("Should provision new tenant successfully")
    void testCreateTenant() {
        TenantCreateRequest request = new TenantCreateRequest(
            "tenant-neo-bank",
            "NeoBank Digital",
            TenantTier.PROFESSIONAL,
            8000,
            60,
            List.of("192.168.1.0/24"),
            "admin@neobank.internal",
            "https://hooks.neobank.internal/soc"
        );

        Tenant created = tenantService.createTenant(request);
        assertThat(created).isNotNull();
        assertThat(created.id()).isEqualTo("tenant-neo-bank");
        assertThat(created.tier()).isEqualTo(TenantTier.PROFESSIONAL);
        assertThat(created.status()).isEqualTo(TenantStatus.ACTIVE);

        // Conflict check
        assertThatThrownBy(() -> tenantService.createTenant(request))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("already exists");
    }

    @Test
    @DisplayName("Should update tenant status and quotas")
    void testUpdateStatusAndQuotas() {
        TenantStatusUpdateRequest statusReq = new TenantStatusUpdateRequest(TenantStatus.SUSPENDED, "Administrative review");
        Optional<Tenant> updatedStatus = tenantService.updateStatus("tenant-retail-asia", statusReq);
        assertThat(updatedStatus).isPresent();
        assertThat(updatedStatus.get().status()).isEqualTo(TenantStatus.SUSPENDED);

        TenantQuotaUpdateRequest quotaReq = new TenantQuotaUpdateRequest(7500, 120, List.of("10.50.0.0/16"));
        Optional<Tenant> updatedQuota = tenantService.updateQuotas("tenant-retail-asia", quotaReq);
        assertThat(updatedQuota).isPresent();
        assertThat(updatedQuota.get().rateLimitRpm()).isEqualTo(7500);
        assertThat(updatedQuota.get().maxIncidentsRetentionDays()).isEqualTo(120);
        assertThat(updatedQuota.get().allowedIpRanges()).containsExactly("10.50.0.0/16");
    }

    @Test
    @DisplayName("Should compute tenant usage and quota headroom")
    void testGetTenantUsage() {
        when(apiEventRepository.findEvents(anyInt(), anyInt(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), anyString()))
            .thenReturn(new SecurityEventPageResponse(Collections.emptyList(), 0, 1, 1500L, 1500, true, false));
        when(incidentRepository.countOpenIncidents()).thenReturn(2L);

        Optional<TenantUsageResponse> usage = tenantService.getTenantUsage("tenant-fintech-us");
        assertThat(usage).isPresent();
        assertThat(usage.get().tenantId()).isEqualTo("tenant-fintech-us");
        assertThat(usage.get().rateLimitRpm()).isEqualTo(10000);
        assertThat(usage.get().totalRecordedEvents()).isEqualTo(1500L);
        assertThat(usage.get().activeIncidentsCount()).isEqualTo(2);
        assertThat(usage.get().rateLimitUtilizationPercent()).isGreaterThan(0.0);
    }
}
