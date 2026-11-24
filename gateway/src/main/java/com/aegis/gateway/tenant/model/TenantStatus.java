package com.aegis.gateway.tenant.model;

/**
 * Operational lifecycle status for a SaaS tenant.
 */
public enum TenantStatus {
    ACTIVE,
    SUSPENDED,
    PROVISIONING,
    DECOMMISSIONED
}
