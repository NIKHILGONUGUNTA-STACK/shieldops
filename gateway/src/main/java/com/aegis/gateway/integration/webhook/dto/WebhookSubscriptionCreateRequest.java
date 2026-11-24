package com.aegis.gateway.integration.webhook.dto;

import com.aegis.gateway.integration.webhook.model.WebhookEventType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

import java.util.List;

public record WebhookSubscriptionCreateRequest(
    String tenantId,

    @NotBlank
    String name,

    @NotBlank
    @URL
    String targetUrl,

    String secretToken,

    @NotEmpty
    List<WebhookEventType> eventTypes
) {}
