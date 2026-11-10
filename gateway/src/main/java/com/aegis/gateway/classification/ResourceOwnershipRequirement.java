package com.aegis.gateway.classification;

/**
 * Resource ownership requirement associated with sensitive fields.
 */
public enum ResourceOwnershipRequirement {
    /**
     * No ownership required (public data or system information).
     */
    NONE,

    /**
     * Caller must be the verified owner of the resource (customer ID matches resource customerId).
     */
    OWNER_CUSTOMER,

    /**
     * Accessible only by internal trusted services via internal mTLS/trust headers.
     */
    INTERNAL_SERVICE,

    /**
     * Accessible only by authorized security personnel (SECURITY_ANALYST, SECURITY_ADMIN).
     */
    ANALYST_ROLE
}

