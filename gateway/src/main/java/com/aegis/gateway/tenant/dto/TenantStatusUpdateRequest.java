package com.aegis.gateway.tenant.dto;

import com.aegis.gateway.tenant.model.TenantStatus;
import jakarta.validation.constraints.NotNull;

public record TenantStatusUpdateRequest(
    @NotNull
    TenantStatus status,

    String reason
) {}
