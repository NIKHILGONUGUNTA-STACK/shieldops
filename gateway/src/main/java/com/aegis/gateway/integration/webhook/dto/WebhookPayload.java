package com.aegis.gateway.integration.webhook.dto;

import com.aegis.gateway.integration.webhook.model.WebhookEventType;
import java.time.Instant;
import java.util.Map;

/**
 * Outbound JSON payload delivered to external webhook endpoints.
 */
public record WebhookPayload(
    String eventId,
    WebhookEventType eventType,
    Instant timestamp,
    String tenantId,
    String severity,
    String title,
    String summary,
    Map<String, Object> details
) {}
