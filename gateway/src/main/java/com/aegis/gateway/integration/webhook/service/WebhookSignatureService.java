package com.aegis.gateway.integration.webhook.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Service generating HMAC-SHA256 signatures for tamper-proof webhook payload delivery.
 */
@Service
public class WebhookSignatureService {

    private static final Logger log = LoggerFactory.getLogger(WebhookSignatureService.class);
    private static final String HMAC_SHA256 = "HmacSHA256";

    /**
     * Computes HMAC-SHA256 signature in format "sha256=<hex>".
     */
    public String calculateSignature(String payloadJson, String secret) {
        if (secret == null || secret.isBlank()) {
            return "sha256=unsigned";
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(payloadJson.getBytes(StandardCharsets.UTF_8));
            return "sha256=" + HexFormat.of().formatHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Failed to compute webhook HMAC signature: {}", e.getMessage(), e);
            return "sha256=error";
        }
    }
}
