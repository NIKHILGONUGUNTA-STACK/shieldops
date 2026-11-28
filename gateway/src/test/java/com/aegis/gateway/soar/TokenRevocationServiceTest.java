package com.aegis.gateway.soar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class TokenRevocationServiceTest {

    private TokenRevocationService service;

    @BeforeEach
    void setUp() {
        service = new TokenRevocationService(null);
    }

    @Test
    void testRevokeByJti() {
        String testJti = "jti-test-12345";
        assertThat(service.isRevoked(testJti, "user.one", Instant.now())).isFalse();

        TokenRevocationRecord record = service.revokeToken(testJti, "user.one", "Stolen Token", Duration.ofHours(2));
        assertThat(record).isNotNull();
        assertThat(service.isRevoked(testJti, "user.one", Instant.now())).isTrue();
    }

    @Test
    void testRevokeBySubjectCutoff() {
        String subject = "compromised.user";
        Instant beforeRevoke = Instant.now().minusSeconds(60);

        assertThat(service.isRevoked("jti-other", subject, beforeRevoke)).isFalse();

        service.revokeSubject(subject, "Credential stuffing confirmed", Duration.ofHours(12));

        // Tokens issued BEFORE cutoff must be revoked
        assertThat(service.isRevoked("jti-old", subject, beforeRevoke)).isTrue();

        // Tokens issued AFTER cutoff are valid
        Instant afterRevoke = Instant.now().plusSeconds(10);
        assertThat(service.isRevoked("jti-new", subject, afterRevoke)).isFalse();
    }

    @Test
    void testGetRevokedTokens() {
        service.revokeToken("jti-list-1", "user.a", "Test Reason 1", Duration.ofHours(1));
        service.revokeToken("jti-list-2", "user.b", "Test Reason 2", Duration.ofHours(1));

        assertThat(service.getRevokedTokens().size()).isGreaterThanOrEqualTo(2);
    }
}
