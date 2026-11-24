package com.aegis.gateway.integration.webhook.dto;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;

public record WebhookTestDispatchRequest(
    @NotBlank
    @URL
    String targetUrl,

    String secretToken,

    String message
) {}
