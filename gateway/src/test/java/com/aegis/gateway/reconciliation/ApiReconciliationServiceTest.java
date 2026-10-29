package com.aegis.gateway.reconciliation;

import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationItemResponse;
import com.aegis.gateway.reconciliation.dto.ReconciliationPageResponse;
import com.aegis.gateway.reconciliation.dto.ReconciliationSummaryResponse;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiReconciliationServiceTest {

    @Mock
    private ApiReconciliationRepository repository;

    private ApiReconciliationService service;

    private final UUID specId1 = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private final UUID specId2 = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @BeforeEach
    void setUp() {
        service = new ApiReconciliationService(repository);
    }

    @Test
    @DisplayName("Exact route-and-method match should classify as MATCHED with request counts")
    void testExactMatch() {
        Instant now = Instant.now();
        Instant past = now.minus(2, ChronoUnit.HOURS);

        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Customer API", "1.0.0",
                "GET", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}",
                "getCustomer", "customer-service"
            )
        );

        var observed = List.of(
            new ApiReconciliationRepository.RawObservedOperation(
                "GET", "/api/v1/customers/12345", 50L, past, now,
                48L, 0L, 2L, 0L
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(observed);

        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, null, "category", "asc"
        );

        assertThat(page.content()).hasSize(1);
        ReconciliationItemResponse item = page.content().get(0);
        assertThat(item.category()).isEqualTo(ReconciliationCategory.MATCHED);
        assertThat(item.httpMethod()).isEqualTo("GET");
        assertThat(item.normalizedRoute()).isEqualTo("/api/v1/customers/{customerId}");
        assertThat(item.totalRequests()).isEqualTo(50L);
        assertThat(item.statusDistribution()).containsEntry("2xx", 48L);
        assertThat(item.statusDistribution()).containsEntry("4xx", 2L);
        assertThat(item.explanation()).contains("Declared in specification 'Customer API'");

        assertThat(page.summary().matchedCount()).isEqualTo(1);
        assertThat(page.summary().coveragePercentage()).isEqualTo(100.0);
    }

    @Test
    @DisplayName("Observed route absent from specification should classify as OBSERVED_UNDOCUMENTED")
    void testObservedUndocumented() {
        Instant now = Instant.now();

        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Customer API", "1.0.0",
                "GET", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}",
                "getCustomer", "customer-service"
            )
        );

        var observed = List.of(
            new ApiReconciliationRepository.RawObservedOperation(
                "POST", "/internal/debug/reset", 5L, now.minusSeconds(60), now,
                5L, 0L, 0L, 0L
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(observed);

        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, null, "category", "asc"
        );

        assertThat(page.content()).hasSize(2); // 1 undocumented + 1 unobserved
        var undocumented = page.content().stream()
            .filter(i -> i.category() == ReconciliationCategory.OBSERVED_UNDOCUMENTED)
            .findFirst()
            .orElseThrow();

        assertThat(undocumented.normalizedRoute()).isEqualTo("/internal/debug/reset");
        assertThat(undocumented.httpMethod()).isEqualTo("POST");
        assertThat(undocumented.totalRequests()).isEqualTo(5L);
        assertThat(undocumented.specificationName()).isNull();
    }

    @Test
    @DisplayName("Declared operation with zero traffic in window should classify as DOCUMENTED_UNOBSERVED")
    void testDocumentedUnobserved() {
        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Customer API", "1.0.0",
                "DELETE", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}",
                "deleteCustomer", "customer-service"
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(List.of());

        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, null, "category", "asc"
        );

        assertThat(page.content()).hasSize(1);
        ReconciliationItemResponse item = page.content().get(0);
        assertThat(item.category()).isEqualTo(ReconciliationCategory.DOCUMENTED_UNOBSERVED);
        assertThat(item.totalRequests()).isZero();
        assertThat(item.specificationName()).isEqualTo("Customer API");
        assertThat(item.explanation()).contains("no wire telemetry was observed");
        assertThat(page.summary().coveragePercentage()).isZero();
    }

    @Test
    @DisplayName("Observed method not matching declared methods for route should classify as METHOD_MISMATCH")
    void testMethodMismatch() {
        Instant now = Instant.now();

        // Spec declares GET only on /api/v1/accounts/{accountId}
        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Account API", "1.0.0",
                "GET", "/api/v1/accounts/{id}", "/api/v1/accounts/{accountId}",
                "getAccount", "account-service"
            )
        );

        // Telemetry observed DELETE on /api/v1/accounts/9999
        var observed = List.of(
            new ApiReconciliationRepository.RawObservedOperation(
                "DELETE", "/api/v1/accounts/9999", 3L, now.minusSeconds(100), now,
                0L, 0L, 3L, 0L
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(observed);

        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, null, "category", "asc"
        );

        var mismatch = page.content().stream()
            .filter(i -> i.category() == ReconciliationCategory.METHOD_MISMATCH)
            .findFirst()
            .orElseThrow();

        assertThat(mismatch.httpMethod()).isEqualTo("DELETE");
        assertThat(mismatch.normalizedRoute()).isEqualTo("/api/v1/accounts/{accountId}");
        assertThat(mismatch.declaredMethodsForRoute()).contains("GET");
        assertThat(mismatch.explanation()).contains("Observed HTTP DELETE on route /api/v1/accounts/{accountId}");
    }

    @Test
    @DisplayName("Multiple specifications declaring conflicting service boundaries should classify as AMBIGUOUS")
    void testAmbiguousOverlappingSpecs() {
        // Spec 1 declares /api/v1/tokens as auth-service
        // Spec 2 declares /api/v1/tokens as gateway-service
        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Auth Spec", "1.0.0",
                "POST", "/api/v1/tokens", "/api/v1/tokens",
                "createToken", "auth-service"
            ),
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId2, "Gateway Spec", "2.0.0",
                "POST", "/api/v1/tokens", "/api/v1/tokens",
                "issueToken", "gateway-service"
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(List.of());

        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, null, "category", "asc"
        );

        var ambiguous = page.content().stream()
            .filter(i -> i.category() == ReconciliationCategory.AMBIGUOUS)
            .findFirst()
            .orElseThrow();

        assertThat(ambiguous.normalizedRoute()).isEqualTo("/api/v1/tokens");
        assertThat(ambiguous.explanation()).contains("conflicting service boundaries");
    }

    @Test
    @DisplayName("Window validation rejects invalid from-to range and excess duration")
    void testWindowValidation() {
        Instant now = Instant.now();
        Instant future = now.plus(1, ChronoUnit.DAYS);

        // 'from' after 'to'
        assertThatThrownBy(() -> service.resolveWindow(null, future, now))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must be before or equal to");

        // window exceeding 30 days
        Instant thirtyFiveDaysAgo = now.minus(35, ChronoUnit.DAYS);
        assertThatThrownBy(() -> service.resolveWindow(null, thirtyFiveDaysAgo, now))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("exceeds maximum retention limit");

        // negative/zero windowHours
        assertThatThrownBy(() -> service.resolveWindow(0, null, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("windowHours must be between");
    }

    @Test
    @DisplayName("Filter and search should narrow down results correctly")
    void testFilteringAndSearch() {
        var declared = List.of(
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Customer API", "1.0.0",
                "GET", "/api/v1/customers/{id}", "/api/v1/customers/{customerId}",
                "getCustomer", "customer-service"
            ),
            new ApiReconciliationRepository.RawDeclaredOperation(
                UUID.randomUUID(), specId1, "Account API", "1.0.0",
                "POST", "/api/v1/accounts", "/api/v1/accounts",
                "createAccount", "account-service"
            )
        );

        when(repository.findDeclaredOperations(null)).thenReturn(declared);
        when(repository.findObservedOperationsInWindow(any(), any(), isNull())).thenReturn(List.of());

        // Search for 'account'
        ReconciliationPageResponse page = service.reconcile(
            0, 20, null, null, null, null, 24, null, null, "account", "category", "asc"
        );

        assertThat(page.content()).hasSize(1);
        assertThat(page.content().get(0).normalizedRoute()).isEqualTo("/api/v1/accounts");
    }
}

