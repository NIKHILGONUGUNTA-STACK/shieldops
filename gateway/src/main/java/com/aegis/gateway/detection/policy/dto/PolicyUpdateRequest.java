package com.aegis.gateway.detection.policy.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PolicyUpdateRequest(
    Boolean enabled,
    @DecimalMin("0.0") @DecimalMax("100.0") Double riskThreshold,
    @Size(max = 255) String description,
    @NotBlank(message = "Audit reason is required for policy modifications")
    @Size(min = 5, max = 512)
    String changeReason
) {}
