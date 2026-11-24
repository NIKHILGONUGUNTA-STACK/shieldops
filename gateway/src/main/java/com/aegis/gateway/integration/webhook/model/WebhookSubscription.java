package com.aegis.gateway.integration.webhook.model;

import java.time.Instant;
import java.util.List;

/**
 * Webhook subscription configuration entity.
 */
public record WebhookSubscription(
    String id,
    String tenantId,
    String name,
    String targetUrl,
    String secretToken,
    List<WebhookEventType> eventTypes,
    boolean enabled,
    Instant createdAt,
    Instant lastTriggeredAt,
    Integer lastStatusCode,
    long successCount,
    long failureCount
) {
    public WebhookSubscription withTriggerResult(int statusCode, boolean success) {
        return new WebhookSubscription(
            id, tenantId, name, targetUrl, secretToken, eventTypes, enabled,
            createdAt, Instant.now(), statusCode,
            success ? successCount + 1 : successCount,
            success ? failureCount : failureCount + 1
        );
    }

    public WebhookSubscription withEnabled(boolean newEnabled) {
        return new WebhookSubscription(
            id, tenantId, name, targetUrl, secretToken, eventTypes, newEnabled,
            createdAt, lastTriggeredAt, lastStatusCode, successCount, failureCount
        );
    }
}
