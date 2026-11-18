package com.aegis.gateway.soc;

import com.aegis.gateway.soc.model.*;
import com.aegis.gateway.soc.service.SocOperationsService;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.aegis.gateway.telemetry.SecurityEventResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
public class SocOperationsIntegrationTest {

    @Autowired
    private SocOperationsService socOperationsService;

    @Autowired
    private ApiEventRepository apiEventRepository;

    @Test
    @DisplayName("Verify Network Intelligence aggregates observed IPs and assigns local reputation")
    void testNetworkIntelligenceAggregation() {
        String testIp = "192.168.1.199";
        UUID eventId1 = UUID.randomUUID();
        UUID eventId2 = UUID.randomUUID();

        apiEventRepository.save(new ApiEvent(
            eventId1,
            UUID.randomUUID().toString(),
            Instant.now(),
            testIp,
            "GET",
            "/api/v1/customers",
            "/api/v1/customers",
            200,
            15L,
            "user-1",
            "ROLE_USER",
            "CUST-1",
            "curl/8.0",
            null,
            "NONE",
            "CUSTOMER",
            null,
            null,
            200L,
            1,
            null,
            0,
            20,
            null,
            null,
            null,
            null,
            "tenant-ops-1",
            "customer-service"
        ));

        apiEventRepository.save(new ApiEvent(
            eventId2,
            UUID.randomUUID().toString(),
            Instant.now(),
            testIp,
            "GET",
            "/api/v1/accounts",
            "/api/v1/accounts",
            403,
            20L,
            "user-1",
            "ROLE_USER",
            "CUST-1",
            "curl/8.0",
            null,
            "BOLA_SUSPICION",
            "ACCOUNT",
            null,
            "FORBIDDEN",
            50L,
            0,
            null,
            0,
            20,
            null,
            null,
            null,
            null,
            "tenant-ops-1",
            "account-service"
        ));

        NetworkIntelligenceResponse response = socOperationsService.getNetworkIntelligence(24, 50);
        assertThat(response).isNotNull();
        assertThat(response.observedIps()).isNotEmpty();

        ObservedIpRecord target = response.observedIps().stream()
            .filter(r -> testIp.equals(r.ipAddress()))
            .findFirst()
            .orElse(null);

        assertThat(target).isNotNull();
        assertThat(target.totalRequests()).isGreaterThanOrEqualTo(2);
        assertThat(target.requests2xx()).isGreaterThanOrEqualTo(1);
        assertThat(target.requests4xx()).isGreaterThanOrEqualTo(1);
        assertThat(target.reputationStatus()).isEqualTo("INTERNAL_NETWORK");
        assertThat(target.reputationSource()).isEqualTo("LOCAL_EVALUATION");
    }

    @Test
    @DisplayName("Verify Identity Intelligence aggregates observed subjects and risk categories")
    void testIdentityIntelligenceAggregation() {
        String subject = "subject-ops-" + UUID.randomUUID().toString().substring(0, 6);
        UUID eventId = UUID.randomUUID();

        apiEventRepository.save(new ApiEvent(
            eventId,
            UUID.randomUUID().toString(),
            Instant.now(),
            "10.0.0.99",
            "POST",
            "/api/v1/transfers",
            "/api/v1/transfers",
            200,
            35L,
            subject,
            "ROLE_ANALYST",
            "CUST-999",
            "Browser",
            null,
            "NONE",
            "TRANSFER",
            null,
            null,
            150L,
            1,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            "tenant-ops-2",
            "transaction-service"
        ));

        IdentityIntelligenceResponse response = socOperationsService.getIdentityIntelligence(24, 50);
        assertThat(response).isNotNull();

        ObservedIdentityRecord identity = response.observedIdentities().stream()
            .filter(r -> subject.equals(r.subject()))
            .findFirst()
            .orElse(null);

        assertThat(identity).isNotNull();
        assertThat(identity.subject()).isEqualTo(subject);
        assertThat(identity.customerId()).isEqualTo("CUST-999");
        assertThat(identity.roles()).isEqualTo("ROLE_ANALYST");
        assertThat(identity.totalRequests()).isGreaterThanOrEqualTo(1);
        assertThat(identity.riskCategory()).isNotNull();
    }

    @Test
    @DisplayName("Verify Tenant Activity aggregates tenant request counts and identities")
    void testTenantActivityAggregation() {
        String tenantId = "tenant-activity-" + UUID.randomUUID().toString().substring(0, 6);
        UUID eventId = UUID.randomUUID();

        apiEventRepository.save(new ApiEvent(
            eventId,
            UUID.randomUUID().toString(),
            Instant.now(),
            "127.0.0.1",
            "GET",
            "/api/v1/customers",
            "/api/v1/customers",
            200,
            10L,
            "user-alpha",
            "ROLE_USER",
            null,
            "curl",
            null,
            "NONE",
            "CUSTOMER",
            null,
            null,
            100L,
            1,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            tenantId,
            "customer-service"
        ));

        TenantActivityResponse response = socOperationsService.getTenantActivity(24, 50);
        assertThat(response).isNotNull();

        TenantActivityRecord tenantRecord = response.tenants().stream()
            .filter(t -> tenantId.equals(t.tenantId()))
            .findFirst()
            .orElse(null);

        assertThat(tenantRecord).isNotNull();
        assertThat(tenantRecord.tenantId()).isEqualTo(tenantId);
        assertThat(tenantRecord.totalRequests()).isGreaterThanOrEqualTo(1);
        assertThat(tenantRecord.uniqueIdentitiesCount()).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("Verify Infrastructure Observability reports live JVM, database and pipeline metrics")
    void testInfrastructureObservability() {
        InfrastructureObservabilityResponse response = socOperationsService.getInfrastructureObservability();
        assertThat(response).isNotNull();
        assertThat(response.gatewayStatus()).isIn("HEALTHY", "DEGRADED");
        assertThat(response.uptimeSeconds()).isGreaterThanOrEqualTo(0);

        // JVM Metrics
        assertThat(response.jvm()).isNotNull();
        assertThat(response.jvm().heapUsedBytes()).isGreaterThan(0);
        assertThat(response.jvm().heapMaxBytes()).isGreaterThan(0);
        assertThat(response.jvm().activeThreads()).isGreaterThan(0);

        // Database Metrics
        assertThat(response.database()).isNotNull();
        assertThat(response.database().status()).isIn("CONNECTED", "DEGRADED", "UNAVAILABLE");

        // Redis Metrics
        assertThat(response.redis()).isNotNull();
        assertThat(response.redis().streamKey()).isEqualTo("test:stream:api-events");

        // Telemetry Pipeline Metrics
        assertThat(response.telemetryPipeline()).isNotNull();
        assertThat(response.telemetryPipeline().totalEventsPersisted()).isGreaterThanOrEqualTo(0);
    }

    @Test
    @DisplayName("Verify correlation navigation finds events matching correlationId chronologically")
    void testCorrelationNavigation() {
        String testCorrelationId = "CORR-NAV-" + UUID.randomUUID().toString().substring(0, 8);
        UUID event1 = UUID.randomUUID();
        UUID event2 = UUID.randomUUID();

        apiEventRepository.save(new ApiEvent(
            event1,
            testCorrelationId,
            Instant.now().minusSeconds(5),
            "127.0.0.1",
            "GET",
            "/api/v1/customers",
            "/api/v1/customers",
            200,
            10L,
            null,
            null,
            null,
            null,
            null,
            "NONE",
            null,
            null,
            null,
            100L,
            1,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            "customer-service"
        ));

        apiEventRepository.save(new ApiEvent(
            event2,
            testCorrelationId,
            Instant.now(),
            "127.0.0.1",
            "GET",
            "/api/v1/accounts",
            "/api/v1/accounts",
            200,
            15L,
            null,
            null,
            null,
            null,
            null,
            "NONE",
            null,
            null,
            null,
            120L,
            1,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            "account-service"
        ));

        List<SecurityEventResponse> correlationEvents = apiEventRepository.findByCorrelationId(testCorrelationId);
        assertThat(correlationEvents).hasSize(2);
        assertThat(correlationEvents.get(0).id()).isEqualTo(event1);
        assertThat(correlationEvents.get(1).id()).isEqualTo(event2);
        assertThat(correlationEvents.get(0).correlationId()).isEqualTo(testCorrelationId);
    }
}
