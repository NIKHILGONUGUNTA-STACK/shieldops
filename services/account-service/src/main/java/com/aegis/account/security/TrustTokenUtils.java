package com.aegis.account.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

public final class TrustTokenUtils {
    public static final String SIGNATURE_HEADER = "X-Aegis-Internal-Signature";
    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    public static final String USER_ID_HEADER = "X-Aegis-User-Id";
    public static final String CUSTOMER_ID_HEADER = "X-Aegis-Customer-Id";
    public static final String ROLES_HEADER = "X-Aegis-Roles";

    private TrustTokenUtils() {}

    public static String buildAttestationHeader(String correlationId, String userId, String secret) {
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String signature = computeSignature(timestamp, correlationId, userId, secret);
        return "t=" + timestamp + ";sig=" + signature;
    }

    public static boolean verifyAttestationHeader(String headerValue, String correlationId, String userId, String secret, long maxDriftSeconds) {
        if (headerValue == null || headerValue.isBlank() || secret == null || secret.isBlank()) {
            return false;
        }

        String timestamp = null;
        String signature = null;
        String[] parts = headerValue.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith("t=")) {
                timestamp = trimmed.substring(2);
            } else if (trimmed.startsWith("sig=")) {
                signature = trimmed.substring(4);
            }
        }

        if (timestamp == null || signature == null) {
            return false;
        }

        try {
            long ts = Long.parseLong(timestamp);
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - ts) > maxDriftSeconds) {
                return false;
            }

            String expectedSignature = computeSignature(timestamp, correlationId, userId, secret);
            return MessageDigest.isEqual(
                signature.getBytes(StandardCharsets.UTF_8),
                expectedSignature.getBytes(StandardCharsets.UTF_8)
            );
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static String computeSignature(String timestamp, String correlationId, String userId, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            String payload = timestamp + ":" + (correlationId != null ? correlationId : "") + ":" + (userId != null ? userId : "");
            byte[] hmac = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmac);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute HMAC-SHA256", e);
        }
    }
}
