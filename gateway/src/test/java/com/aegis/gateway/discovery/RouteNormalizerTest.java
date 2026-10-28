package com.aegis.gateway.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RouteNormalizerTest {

    @Test
    @DisplayName("Normalizes customer profile paths with UUID to semantic template")
    void normalizeCustomerProfile() {
        String uri = "/api/v1/customers/c8d5040e-7db7-44f2-95f3-52467d5ce87b/profile";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/customers/{customerId}/profile");
    }

    @Test
    @DisplayName("Normalizes customer resource with UUID to semantic template")
    void normalizeCustomerById() {
        String uri = "/api/v1/customers/00000000-0000-0000-0000-000000000001";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/customers/{customerId}");
    }

    @Test
    @DisplayName("Normalizes account balance with ACCT reference and balance subresource")
    void normalizeAccountBalanceWithRef() {
        String uri = "/api/v1/accounts/ACCT-992384/balance";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/accounts/{accountId}/balance");
    }

    @Test
    @DisplayName("Normalizes account debit with UUID")
    void normalizeAccountDebit() {
        String uri = "/api/v1/accounts/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d/debit";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/accounts/{accountId}/debit");
    }

    @Test
    @DisplayName("Normalizes beneficiary verification endpoint")
    void normalizeBeneficiaryVerify() {
        String uri = "/api/v1/beneficiaries/10000000-0000-4000-8000-000000000001/verify";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/beneficiaries/{beneficiaryId}/verify");
    }

    @Test
    @DisplayName("Normalizes transaction detail endpoint")
    void normalizeTransactionById() {
        String uri = "/api/v1/transactions/TX-99887766";
        String normalized = RouteNormalizer.normalize(uri);
        assertThat(normalized).isEqualTo("/api/v1/transactions/{transactionId}");
    }

    @Test
    @DisplayName("Normalizes security incident subresources")
    void normalizeSecurityIncidentSubresources() {
        assertThat(RouteNormalizer.normalize("/api/v1/security/incidents/00000000-0000-0000-0000-000000000001/evidence"))
            .isEqualTo("/api/v1/security/incidents/{incidentId}/evidence");

        assertThat(RouteNormalizer.normalize("/api/v1/security/incidents/00000000-0000-0000-0000-000000000001/status"))
            .isEqualTo("/api/v1/security/incidents/{incidentId}/status");
    }

    @Test
    @DisplayName("Completely strips query strings, access tokens, and sensitive params")
    void stripsQueryStrings() {
        String uriWithQuery = "/api/v1/accounts?customerId=12345&token=secretBearerToken999";
        String normalized = RouteNormalizer.normalize(uriWithQuery);
        assertThat(normalized).isEqualTo("/api/v1/accounts");
        assertThat(normalized).doesNotContain("customerId", "token", "secretBearerToken999", "?");
    }

    @Test
    @DisplayName("Resolves correct service boundaries for downstream components")
    void resolvesServiceBoundaries() {
        assertThat(RouteNormalizer.resolveService("/api/v1/customers/{customerId}")).isEqualTo("customer-service");
        assertThat(RouteNormalizer.resolveService("/api/v1/accounts/{accountId}/balance")).isEqualTo("account-service");
        assertThat(RouteNormalizer.resolveService("/api/v1/beneficiaries")).isEqualTo("transaction-service");
        assertThat(RouteNormalizer.resolveService("/api/v1/transfers")).isEqualTo("transaction-service");
        assertThat(RouteNormalizer.resolveService("/api/v1/security/incidents")).isEqualTo("security-gateway");
        assertThat(RouteNormalizer.resolveService("/actuator/health")).isEqualTo("aegis-gateway");
    }

    @Test
    @DisplayName("Generates deterministic stable endpoint IDs")
    void generatesDeterministicEndpointId() {
        String id1 = RouteNormalizer.generateEndpointId("GET", "/api/v1/customers/{customerId}");
        String id2 = RouteNormalizer.generateEndpointId("get", " /api/v1/customers/{customerId} ");
        String idDiffMethod = RouteNormalizer.generateEndpointId("POST", "/api/v1/customers/{customerId}");

        assertThat(id1).startsWith("ep_");
        assertThat(id1).isEqualTo(id2);
        assertThat(id1).isNotEqualTo(idDiffMethod);
    }
}
