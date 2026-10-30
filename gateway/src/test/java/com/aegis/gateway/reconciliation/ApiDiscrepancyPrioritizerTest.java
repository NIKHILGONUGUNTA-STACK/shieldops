package com.aegis.gateway.reconciliation;

import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationPrioritizationResult;
import com.aegis.gateway.reconciliation.dto.ReconciliationPriority;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ApiDiscrepancyPrioritizerTest {

    private ApiDiscrepancyPrioritizer prioritizer;

    @BeforeEach
    void setUp() {
        prioritizer = new ApiDiscrepancyPrioritizer();
    }

    @Test
    void shouldPrioritizeObservedUndocumentedRouteWithCriticalityAndAuthFailures() {
        Instant now = Instant.now();
        Instant first = now.minus(14, ChronoUnit.HOURS);

        ReconciliationPrioritizationResult result = prioritizer.prioritize(
            ReconciliationCategory.OBSERVED_UNDOCUMENTED,
            "/api/v1/transfers/internal",
            "transaction-service",
            1200L,
            60L,
            2L,
            first,
            now,
            false
        );

        // Expected score:
        // Base: 35 (UNDOCUMENTED)
        // Criticality: 20 (transaction-service / transfers)
        // Security signals: 25 (auth >= 50) + 15 (anomaly) = 40
        // Exposure: 10 (reqs >= 1000)
        // Persistence: 5 (span >= 12h)
        // Total = 110 -> bounded to 100
        assertThat(result.score()).isEqualTo(100);
        assertThat(result.priority()).isEqualTo(ReconciliationPriority.CRITICAL);
        assertThat(result.ruleVersion()).isEqualTo("v1.0.0");
        assertThat(result.contributingFactors()).isNotEmpty();
        assertThat(result.matchingConfidence()).isEqualTo("HIGH");
    }

    @Test
    void shouldKeepHighVolumeBenignTrafficAtLowPriorityWhenMatchedAndNoSecuritySignals() {
        Instant now = Instant.now();
        Instant first = now.minus(20, ChronoUnit.HOURS);

        ReconciliationPrioritizationResult result = prioritizer.prioritize(
            ReconciliationCategory.MATCHED,
            "/api/v1/customers/{customerId}",
            "customer-service",
            50000L, // High volume benign traffic
            0L,     // Zero auth failures
            0L,     // Zero anomaly flags
            first,
            now,
            false
        );

        // Expected score:
        // Base: 0 (MATCHED)
        // Criticality: 10 (customer-service)
        // Security signals: 0
        // Exposure: 10 (reqs >= 1000)
        // Persistence: 5 (span >= 12h)
        // Total: 25 -> MEDIUM (barely touches 25 due to persistence and customer service, strictly bounded, NOT Critical or High)
        assertThat(result.score()).isEqualTo(25);
        assertThat(result.priority()).isEqualTo(ReconciliationPriority.MEDIUM);
        assertThat(result.matchingConfidence()).isEqualTo("HIGH");
    }

    @Test
    void shouldScoreDocumentedUnobservedEndpointLowPriority() {
        ReconciliationPrioritizationResult result = prioritizer.prioritize(
            ReconciliationCategory.DOCUMENTED_UNOBSERVED,
            "/api/v1/customers/{customerId}/archive",
            "customer-service",
            0L,
            0L,
            0L,
            null,
            null,
            false
        );

        // Expected score:
        // Base: 10 (DOCUMENTED_UNOBSERVED)
        // Criticality: 10 (customer-service)
        // Total: 20 -> LOW
        assertThat(result.score()).isEqualTo(20);
        assertThat(result.priority()).isEqualTo(ReconciliationPriority.LOW);
        assertThat(result.matchingConfidence()).isEqualTo("HIGH");
    }

    @Test
    void shouldScoreMethodMismatchOnSensitiveRouteWithMediumOrHighPriority() {
        ReconciliationPrioritizationResult result = prioritizer.prioritize(
            ReconciliationCategory.METHOD_MISMATCH,
            "/api/v1/accounts/{accountId}/transfer",
            "account-service",
            100L,
            5L,
            0L,
            null,
            null,
            false
        );

        // Expected:
        // Base: 30 (METHOD_MISMATCH)
        // Criticality: 20 (account-service)
        // Security signals: 15 (auth failures: 5)
        // Exposure: 5 (reqs >= 50)
        // Total: 70 -> HIGH
        assertThat(result.score()).isEqualTo(70);
        assertThat(result.priority()).isEqualTo(ReconciliationPriority.HIGH);
    }

    @Test
    void shouldReflectLowConfidenceWhenRouteIsAmbiguous() {
        ReconciliationPrioritizationResult result = prioritizer.prioritize(
            ReconciliationCategory.AMBIGUOUS,
            "/api/v1/notifications",
            "gateway",
            10L,
            0L,
            0L,
            null,
            null,
            true // isAmbiguous = true
        );

        assertThat(result.matchingConfidence()).isEqualTo("LOW");
        assertThat(result.confidenceRationale()).contains("Ambiguous route definition or specification conflict");
        assertThat(result.priority()).isEqualTo(ReconciliationPriority.LOW);
    }

    @Test
    void shouldProduceDeterministicRepeatableScores() {
        Instant now = Instant.now();
        Instant first = now.minus(5, ChronoUnit.HOURS);

        ReconciliationPrioritizationResult run1 = prioritizer.prioritize(
            ReconciliationCategory.OBSERVED_UNDOCUMENTED,
            "/api/v1/internal/health",
            "security-gateway",
            50L,
            0L,
            0L,
            first,
            now,
            false
        );

        ReconciliationPrioritizationResult run2 = prioritizer.prioritize(
            ReconciliationCategory.OBSERVED_UNDOCUMENTED,
            "/api/v1/internal/health",
            "security-gateway",
            50L,
            0L,
            0L,
            first,
            now,
            false
        );

        assertThat(run1.score()).isEqualTo(run2.score());
        assertThat(run1.priority()).isEqualTo(run2.priority());
        assertThat(run1.matchingConfidence()).isEqualTo(run2.matchingConfidence());
    }
}
