package com.aegis.gateway.discovery;

import com.aegis.gateway.discovery.dto.*;
import com.aegis.gateway.reconciliation.ApiDiscrepancyPrioritizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiEndpointIntelligenceTest {

    @Mock
    private ApiDiscoveryRepository discoveryRepository;

    private ApiDiscrepancyPrioritizer prioritizer;
    private ApiDiscoveryService discoveryService;

    private final Instant now = Instant.now();
    private final Instant yesterday = now.minus(24, ChronoUnit.HOURS);

    @BeforeEach
    void setUp() {
        prioritizer = new ApiDiscrepancyPrioritizer();
        discoveryService = new ApiDiscoveryService(discoveryRepository, prioritizer);
    }

    @Test
    @DisplayName("getEndpointIntelligence returns unified dossier for matched endpoint")
    void testGetEndpointIntelligenceMatched() {
        // Setup raw aggregate
        var raw = new ApiDiscoveryRepository.RawEndpointAggregate(
            "GET", "/api/v1/customers/{customerId}", 150L,
            yesterday, now, 42.5, 145L, 0L, 5L, 0L
        );
        when(discoveryRepository.findObservedEndpointAggregates(null)).thenReturn(List.of(raw));
        when(discoveryRepository.findDistinctStatusCodes()).thenReturn(List.of());

        // Setup endpoint queries
        when(discoveryRepository.findDistinctStatusCodesForRoute(eq("GET"), eq("/api/v1/customers/{customerId}"), any(), any()))
            .thenReturn(List.of(200, 404));
        when(discoveryRepository.findSecurityCountsForEndpoint(eq("GET"), eq("/api/v1/customers/{customerId}"), any(), any()))
            .thenReturn(new ApiDiscoveryRepository.SecurityCounts(0L, 0L));

        UUID specId = UUID.randomUUID();
        var specMetadata = new EndpointSpecMetadata(
            specId, "Customer Service API", "1.0.0", 1,
            "getCustomer", "Retrieve customer profile", "Detailed description", "customer", false
        );
        when(discoveryRepository.findDeclaredOperationForEndpoint(eq("GET"), eq("/api/v1/customers/{customerId}")))
            .thenReturn(Optional.of(specMetadata));

        when(discoveryRepository.findLinkedIncidentsForEndpoint(any(), any(), any(), any()))
            .thenReturn(List.of());

        String epId = RouteNormalizer.generateEndpointId("GET", "/api/v1/customers/{customerId}");
        Optional<EndpointIntelligenceResponse> responseOpt = discoveryService.getEndpointIntelligence(epId, 24);

        assertThat(responseOpt).isPresent();
        EndpointIntelligenceResponse response = responseOpt.get();
        assertThat(response.id()).isEqualTo(epId);
        assertThat(response.httpMethod()).isEqualTo("GET");
        assertThat(response.routeTemplate()).isEqualTo("/api/v1/customers/{customerId}");
        assertThat(response.serviceBoundary()).isEqualTo("customer-service");
        assertThat(response.totalRequests()).isEqualTo(150L);
        assertThat(response.distinctStatusCodes()).containsExactly(200, 404);

        // Specification context
        assertThat(response.specification()).isNotNull();
        assertThat(response.specification().specificationName()).isEqualTo("Customer Service API");
        assertThat(response.specification().operationId()).isEqualTo("getCustomer");
        assertThat(response.specification().revisionNumber()).isEqualTo(1);

        // Reconciliation & Prioritization
        assertThat(response.reconciliation().category()).isEqualTo("MATCHED");
        assertThat(response.reconciliation().matchingConfidence()).isEqualTo("HIGH");
        assertThat(response.prioritization().priority()).isEqualTo("LOW");
        assertThat(response.prioritization().confirmedVulnerability()).isFalse();
    }

    @Test
    @DisplayName("getEndpointIntelligence returns undocumented category with elevated priority when auth failures exist")
    void testGetEndpointIntelligenceUndocumentedWithAuthFailures() {
        var raw = new ApiDiscoveryRepository.RawEndpointAggregate(
            "POST", "/api/v1/internal/admin/keys", 85L,
            yesterday, now, 120.0, 70L, 0L, 15L, 0L
        );
        when(discoveryRepository.findObservedEndpointAggregates(null)).thenReturn(List.of(raw));
        when(discoveryRepository.findDistinctStatusCodes()).thenReturn(List.of());

        when(discoveryRepository.findDistinctStatusCodesForRoute(eq("POST"), eq("/api/v1/internal/admin/keys"), any(), any()))
            .thenReturn(List.of(200, 401, 403));
        when(discoveryRepository.findSecurityCountsForEndpoint(eq("POST"), eq("/api/v1/internal/admin/keys"), any(), any()))
            .thenReturn(new ApiDiscoveryRepository.SecurityCounts(15L, 2L));

        when(discoveryRepository.findDeclaredOperationForEndpoint(eq("POST"), eq("/api/v1/internal/admin/keys")))
            .thenReturn(Optional.empty());

        UUID incidentId = UUID.randomUUID();
        when(discoveryRepository.findLinkedIncidentsForEndpoint(any(), any(), any(), any()))
            .thenReturn(List.of(new EndpointLinkedIncident(
                incidentId, "RULE-AUTH-01", "AUTHENTICATION_ABUSE", "HIGH", "OPEN", "Repeated 401 on admin endpoint", now
            )));

        String epId = RouteNormalizer.generateEndpointId("POST", "/api/v1/internal/admin/keys");
        Optional<EndpointIntelligenceResponse> responseOpt = discoveryService.getEndpointIntelligence(epId, 24);

        assertThat(responseOpt).isPresent();
        EndpointIntelligenceResponse response = responseOpt.get();
        assertThat(response.reconciliation().category()).isEqualTo("OBSERVED_UNDOCUMENTED");
        assertThat(response.specification()).isNull();
        assertThat(response.authFailureCount()).isEqualTo(15L);
        assertThat(response.anomalyEventCount()).isEqualTo(2L);

        // Prioritization should be HIGH or CRITICAL due to undocumented (35) + sensitive route (10) + auth failures (20) + anomalies (10)
        assertThat(response.prioritization().priorityScore()).isGreaterThanOrEqualTo(70);
        assertThat(response.prioritization().priority()).isIn("HIGH", "CRITICAL");
        assertThat(response.prioritization().confirmedVulnerability()).isFalse();

        // Linked incidents
        assertThat(response.linkedIncidents()).hasSize(1);
        assertThat(response.linkedIncidents().get(0).ruleId()).isEqualTo("RULE-AUTH-01");
    }

    @Test
    @DisplayName("getEndpointIntelligence returns empty Optional for unknown endpoint ID")
    void testGetEndpointIntelligenceUnknown() {
        when(discoveryRepository.findObservedEndpointAggregates(null)).thenReturn(List.of());
        Optional<EndpointIntelligenceResponse> responseOpt = discoveryService.getEndpointIntelligence("ep_nonexistent", 24);
        assertThat(responseOpt).isEmpty();
    }

    @Test
    @DisplayName("getEndpointObservationHistory generates continuous sequence with zero-filled intervals")
    void testGetEndpointObservationHistoryContinuousBuckets() {
        var raw = new ApiDiscoveryRepository.RawEndpointAggregate(
            "GET", "/api/v1/customers", 20L,
            yesterday, now, 15.0, 20L, 0L, 0L, 0L
        );
        when(discoveryRepository.findObservedEndpointAggregates(null)).thenReturn(List.of(raw));

        Instant bucket1 = now.minus(2, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS);
        Instant bucket2 = now.minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS);

        when(discoveryRepository.findRawObservationBuckets(eq("GET"), eq("/api/v1/customers"), any(), any(), eq("hour")))
            .thenReturn(List.of(
                new ApiDiscoveryRepository.RawObservationBucket(bucket1, 12L, 12L, 0L, 0L, 0L, 14.5, 10L, 20L),
                new ApiDiscoveryRepository.RawObservationBucket(bucket2, 8L, 8L, 0L, 0L, 0L, 16.0, 11L, 25L)
            ));

        String epId = RouteNormalizer.generateEndpointId("GET", "/api/v1/customers");
        Optional<EndpointObservationHistoryResponse> historyOpt = discoveryService.getEndpointObservationHistory(epId, 24, "1h");

        assertThat(historyOpt).isPresent();
        EndpointObservationHistoryResponse history = historyOpt.get();
        assertThat(history.endpointId()).isEqualTo(epId);
        assertThat(history.windowHours()).isEqualTo(24);
        assertThat(history.bucketSize()).isEqualTo("1h");
        assertThat(history.retentionLimitHours()).isEqualTo(720);
        assertThat(history.totalRequests()).isEqualTo(20L);

        // Continuous buckets should span the full 24-25 hours
        assertThat(history.buckets()).hasSizeGreaterThanOrEqualTo(24);

        // Non-empty buckets should have data, empty intervals should be zero-filled
        long nonZeroBuckets = history.buckets().stream().filter(b -> b.requestCount() > 0).count();
        assertThat(nonZeroBuckets).isEqualTo(2L);

        long zeroBuckets = history.buckets().stream().filter(b -> b.requestCount() == 0).count();
        assertThat(zeroBuckets).isGreaterThanOrEqualTo(22L);
    }

    @Test
    @DisplayName("getEndpointSecurityHistory aggregates auth outcomes and security events")
    void testGetEndpointSecurityHistory() {
        var raw = new ApiDiscoveryRepository.RawEndpointAggregate(
            "POST", "/api/v1/transfers", 100L,
            yesterday, now, 50.0, 95L, 0L, 5L, 0L
        );
        when(discoveryRepository.findObservedEndpointAggregates(null)).thenReturn(List.of(raw));

        when(discoveryRepository.findSecurityCountsForEndpoint(eq("POST"), eq("/api/v1/transfers"), any(), any()))
            .thenReturn(new ApiDiscoveryRepository.SecurityCounts(5L, 1L));
        when(discoveryRepository.findDistinctStatusCodesForRoute(eq("POST"), eq("/api/v1/transfers"), any(), any()))
            .thenReturn(List.of(200, 401));

        UUID eventId = UUID.randomUUID();
        when(discoveryRepository.findSecurityEventsForEndpoint(eq("POST"), eq("/api/v1/transfers"), any(), any(), eq(50)))
            .thenReturn(List.of(new EndpointSecurityEvent(
                eventId, now, "10.0.0.5", 401, 35L, "NONE", "user_123"
            )));

        when(discoveryRepository.findLinkedIncidentsForEndpoint(any(), any(), any(), any()))
            .thenReturn(List.of());

        String epId = RouteNormalizer.generateEndpointId("POST", "/api/v1/transfers");
        Optional<EndpointSecurityHistoryResponse> secHistoryOpt = discoveryService.getEndpointSecurityHistory(epId, 24);

        assertThat(secHistoryOpt).isPresent();
        EndpointSecurityHistoryResponse secHistory = secHistoryOpt.get();
        assertThat(secHistory.endpointId()).isEqualTo(epId);
        assertThat(secHistory.authFailureCount()).isEqualTo(5L);
        assertThat(secHistory.anomalyEventCount()).isEqualTo(1L);
        assertThat(secHistory.distinctStatusCodes()).containsExactly(200, 401);
        assertThat(secHistory.securityEvents()).hasSize(1);
        assertThat(secHistory.securityEvents().get(0).statusCode()).isEqualTo(401);
    }
}
