package com.aegis.gateway.integration.webhook.dto;

import java.time.Instant;

public record WebhookDispatchResult(
    String subscriptionId,
    String targetUrl,
    int statusCode,
    boolean success,
    String message,
    long latencyMs,
    Instant timestamp
) {}
