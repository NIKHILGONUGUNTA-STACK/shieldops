package com.aegis.gateway.detection.policy.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PolicyRejectionRequest(
    @NotBlank(message = "Mandatory rejection rationale is required")
    @Size(min = 5, max = 1024, message = "Rejection rationale must be between 5 and 1024 characters")
    String rationale
) {}
