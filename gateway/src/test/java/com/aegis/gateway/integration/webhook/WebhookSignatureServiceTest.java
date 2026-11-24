package com.aegis.gateway.integration.webhook;

import com.aegis.gateway.integration.webhook.service.WebhookSignatureService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WebhookSignatureServiceTest {

    private final WebhookSignatureService signatureService = new WebhookSignatureService();

    @Test
    @DisplayName("Should generate deterministic HMAC-SHA256 signature prefixed with sha256=")
    void testHmacSha256Signature() {
        String payload = "{\"eventId\":\"evt-123\",\"severity\":\"CRITICAL\"}";
        String secret = "secret_key_fintech_2026";

        String signature1 = signatureService.calculateSignature(payload, secret);
        String signature2 = signatureService.calculateSignature(payload, secret);

        assertThat(signature1).startsWith("sha256=");
        assertThat(signature1).isEqualTo(signature2);
        assertThat(signature1.length()).isEqualTo(71); // "sha256=" + 64 hex characters
    }

    @Test
    @DisplayName("Should produce different signatures for different secrets or payloads")
    void testSignatureDifferences() {
        String payload1 = "{\"eventId\":\"1\"}";
        String payload2 = "{\"eventId\":\"2\"}";
        String secret = "test-secret";

        String sig1 = signatureService.calculateSignature(payload1, secret);
        String sig2 = signatureService.calculateSignature(payload2, secret);

        assertThat(sig1).isNotEqualTo(sig2);
    }

    @Test
    @DisplayName("Should return sha256=unsigned when secret is null or blank")
    void testUnsignedWhenBlankSecret() {
        assertThat(signatureService.calculateSignature("{}", null)).isEqualTo("sha256=unsigned");
        assertThat(signatureService.calculateSignature("{}", "")).isEqualTo("sha256=unsigned");
    }
}
