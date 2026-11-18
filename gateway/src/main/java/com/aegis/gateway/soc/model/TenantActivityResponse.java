package com.aegis.gateway.soc.model;

import java.util.List;

public record TenantActivityResponse(
    int windowHours,
    long totalObservedTenants,
    List<TenantActivityRecord> tenants
) {}
