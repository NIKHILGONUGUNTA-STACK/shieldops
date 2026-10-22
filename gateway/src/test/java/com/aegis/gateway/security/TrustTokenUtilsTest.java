package com.aegis.gateway.security;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TrustTokenUtilsTest {
    private static final String SECRET = "unit-test-secret-key-at-least-32-chars!";

    @Test
    void generatesAndVerifiesValidAttestationHeader() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";

        String header = TrustTokenUtils.buildAttestationHeader(correlationId, userId, SECRET);

        assertThat(header).startsWith("t=");
        assertThat(header).contains(";sig=");

        boolean verified = TrustTokenUtils.verifyAttestationHeader(header, correlationId, userId, SECRET, 60);
        assertThat(verified).isTrue();
    }

    @Test
    void generatesAndVerifiesFullAttestationHeader() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        String customerId = "10000000-0000-4000-8000-000000000001";
        String roles = "CUSTOMER";

        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, customerId, roles, "POST", "/api/v1/transfers", SECRET
        );

        boolean verified = TrustTokenUtils.verifyAttestationHeader(
            header, correlationId, userId, customerId, roles, "POST", "/transfers", SECRET, 60
        );
        assertThat(verified).isTrue();
    }

    @Test
    void rejectsAttestationWithMismatchedHttpMethod() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        String customerId = "10000000-0000-4000-8000-000000000001";
        String roles = "CUSTOMER";

        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, customerId, roles, "GET", "/api/v1/transfers", SECRET
        );

        boolean verified = TrustTokenUtils.verifyAttestationHeader(
            header, correlationId, userId, customerId, roles, "POST", "/transfers", SECRET, 60
        );
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsAttestationWithMismatchedPath() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        String customerId = "10000000-0000-4000-8000-000000000001";
        String roles = "CUSTOMER";

        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, customerId, roles, "GET", "/api/v1/customers/1", SECRET
        );

        boolean verified = TrustTokenUtils.verifyAttestationHeader(
            header, correlationId, userId, customerId, roles, "GET", "/accounts/2/debits", SECRET, 60
        );
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsAttestationWithMismatchedCustomerId() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        String roles = "CUSTOMER";

        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, "10000000-0000-4000-8000-000000000001", roles, "GET", "/customers/1", SECRET
        );

        boolean verified = TrustTokenUtils.verifyAttestationHeader(
            header, correlationId, userId, "10000000-0000-4000-8000-000000000002", roles, "GET", "/customers/1", SECRET, 60
        );
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsAttestationWithMismatchedRoles() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        String customerId = "10000000-0000-4000-8000-000000000001";

        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, customerId, "CUSTOMER", "GET", "/customers/1", SECRET
        );

        boolean verified = TrustTokenUtils.verifyAttestationHeader(
            header, correlationId, userId, customerId, "SECURITY_ADMIN", "GET", "/customers/1", SECRET, 60
        );
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsAttestationWithMismatchedCorrelationId() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";

        String header = TrustTokenUtils.buildAttestationHeader(correlationId, userId, SECRET);

        boolean verified = TrustTokenUtils.verifyAttestationHeader(header, "different-correlation-id", userId, SECRET, 60);
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsAttestationWithMismatchedUserId() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";

        String header = TrustTokenUtils.buildAttestationHeader(correlationId, userId, SECRET);

        boolean verified = TrustTokenUtils.verifyAttestationHeader(header, correlationId, "different-user", SECRET, 60);
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsExpiredAttestation() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        long oldTimestamp = Instant.now().getEpochSecond() - 300; // 5 minutes ago
        String sig = TrustTokenUtils.computeSignature(String.valueOf(oldTimestamp), correlationId, userId, SECRET);
        String expiredHeader = "t=" + oldTimestamp + ";sig=" + sig;

        boolean verified = TrustTokenUtils.verifyAttestationHeader(expiredHeader, correlationId, userId, SECRET, 60);
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsFarFutureTimestampAttestation() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";
        long futureTimestamp = Instant.now().getEpochSecond() + 300; // 5 minutes in future
        String sig = TrustTokenUtils.computeSignature(String.valueOf(futureTimestamp), correlationId, userId, SECRET);
        String futureHeader = "t=" + futureTimestamp + ";sig=" + sig;

        boolean verified = TrustTokenUtils.verifyAttestationHeader(futureHeader, correlationId, userId, SECRET, 60);
        assertThat(verified).isFalse();
    }

    @Test
    void rejectsTamperedSignature() {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-abc-123";

        String header = TrustTokenUtils.buildAttestationHeader(correlationId, userId, SECRET);
        String tampered = header.substring(0, header.length() - 4) + "0000";

        boolean verified = TrustTokenUtils.verifyAttestationHeader(tampered, correlationId, userId, SECRET, 60);
        assertThat(verified).isFalse();
    }
}
