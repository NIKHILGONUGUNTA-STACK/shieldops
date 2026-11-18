package com.aegis.gateway.telemetry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
public class TelemetryAttributionIntegrationTest {

    @Autowired
    private ApiEventRepository repository;

    @Test
    @DisplayName("Verify API event attribution fields persist and map correctly")
    void testAttributionFieldsPersistAndMap() {
        UUID eventId = UUID.randomUUID();
        String correlationId = UUID.randomUUID().toString();
        String simRunId = "SIM-RUN-ATTR-1";
        String simCampId = "SIM-CAMP-ATTR-1";
        String simScenId = "SCN-BENIGN-01";
        String simStage = "1";
        String tenantId = "tenant-xyz-99";
        String serviceName = "customer-service";

        ApiEvent event = new ApiEvent(
            eventId,
            correlationId,
            Instant.now(),
            "192.168.1.100",
            "GET",
            "/api/v1/customers/123",
            "/api/v1/customers/{id}",
            200,
            12L,
            "user1",
            "ROLE_USER",
            "CUST-123",
            "Mozilla/5.0",
            null,
            "NONE",
            "CUSTOMER",
            "123",
            null,
            256L,
            1,
            "id,name,email",
            0,
            10,
            simRunId,
            simCampId,
            simScenId,
            simStage,
            tenantId,
            serviceName
        );

        repository.save(event);

        Optional<SecurityEventResponse> retrieved = repository.findById(eventId);
        assertThat(retrieved).isPresent();
        SecurityEventResponse r = retrieved.get();

        assertThat(r.id()).isEqualTo(eventId);
        assertThat(r.correlationId()).isEqualTo(correlationId);
        assertThat(r.simulationRunId()).isEqualTo(simRunId);
        assertThat(r.simulationCampaignId()).isEqualTo(simCampId);
        assertThat(r.simulationScenarioId()).isEqualTo(simScenId);
        assertThat(r.simulationStage()).isEqualTo(simStage);
        assertThat(r.tenantId()).isEqualTo(tenantId);
        assertThat(r.serviceName()).isEqualTo(serviceName);
    }

    @Test
    @DisplayName("Verify absent tenant remains strictly NULL (no default tenant)")
    void testAbsentTenantRemainsNull() {
        UUID eventId = UUID.randomUUID();
        String correlationId = UUID.randomUUID().toString();

        ApiEvent eventWithoutTenant = new ApiEvent(
            eventId,
            correlationId,
            Instant.now(),
            "10.0.0.50",
            "POST",
            "/api/v1/accounts",
            "/api/v1/accounts",
            201,
            25L,
            null,
            null,
            null,
            "curl/7.88.1",
            null,
            "NONE",
            "ACCOUNT",
            null,
            null,
            128L,
            1,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null, // tenantId must remain null
            "account-service"
        );

        repository.save(eventWithoutTenant);

        Optional<SecurityEventResponse> retrieved = repository.findById(eventId);
        assertThat(retrieved).isPresent();
        SecurityEventResponse r = retrieved.get();

        assertThat(r.tenantId()).isNull();
        assertThat(r.serviceName()).isEqualTo("account-service");
        assertThat(r.simulationRunId()).isNull();
    }
}
