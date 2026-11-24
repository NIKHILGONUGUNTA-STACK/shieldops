package com.aegis.gateway.tenant.dto;

import com.aegis.gateway.tenant.model.Tenant;
import java.util.List;

public record TenantPageResponse(
    List<Tenant> content,
    int page,
    int size,
    long totalElements,
    int totalPages
) {}
