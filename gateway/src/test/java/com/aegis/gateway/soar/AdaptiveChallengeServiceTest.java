package com.aegis.gateway.soar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AdaptiveChallengeServiceTest {

    private AdaptiveChallengeService service;

    @BeforeEach
    void setUp() {
        service = new AdaptiveChallengeService();
    }

    @Test
    void testIssueAndVerifyChallenge() {
        String sessionId = "session-test-challenge-1";
        assertThat(service.isCleared(sessionId)).isFalse();

        AdaptiveChallengeService.ChallengeSession session = service.issueChallenge(sessionId, "Suspicious sequence traversal", 0.82);
        assertThat(session).isNotNull();
        assertThat(session.challengeNonce()).startsWith("CHAL-");
        assertThat(session.threatRisk()).isEqualTo(0.82);
        assertThat(session.isChallengeValid()).isTrue();

        // Verification with invalid response token
        boolean failed = service.verifyChallenge(sessionId, "WRONG-TOKEN");
        assertThat(failed).isFalse();
        assertThat(service.isCleared(sessionId)).isFalse();

        // Verification with valid nonce
        boolean success = service.verifyChallenge(sessionId, session.challengeNonce());
        assertThat(success).isTrue();
        assertThat(service.isCleared(sessionId)).isTrue();
    }

    @Test
    void testChallengeMetrics() {
        service.issueChallenge("session-m-1", "Test", 0.75);
        service.issueChallenge("session-m-2", "Test", 0.85);

        Map<String, Object> metrics = service.getMetrics();
        assertThat(metrics.get("totalIssued")).isEqualTo(2L);
    }
}
