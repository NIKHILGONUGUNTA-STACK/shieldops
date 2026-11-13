package com.aegis.gateway.detection.leakage;

/**
 * Categorical taxonomy for Data Leakage and BOLA detection findings.
 */
public enum DataLeakageCategory {
    /**
     * Denied cross-owner access attempt (HTTP 403 on another customer's resource).
     * Represents security evidence / intent, but does not indicate successful data exfiltration.
     */
    BOLA_ATTEMPT("BOLA Attempt (Denied)"),

    /**
     * Confirmed unauthorized cross-owner data exposure (HTTP 200 on another customer's resource).
     * Represents an active, confirmed Broken Object Level Authorization vulnerability.
     */
    BOLA_CONFIRMED_LEAK("Confirmed BOLA Data Leakage"),

    /**
     * Probing campaign following a denied cross-owner attempt (403 followed by rapid probes on adjacent IDs).
     */
    BOLA_PROBE_CAMPAIGN("BOLA Probing Campaign"),

    /**
     * Unexpected exposure of CONFIDENTIAL or RESTRICTED fields to unapproved roles or unauthenticated callers.
     */
    SENSITIVE_DATA_EXPOSURE("Sensitive Data Exposure"),

    /**
     * Field-level exposure anomaly (contract breach, schema drift, unexpected sensitive fields, or unclassified fields).
     */
    EXCESSIVE_DATA_EXPOSURE("Excessive Data Exposure"),

    /**
     * Excessive reads or automated harvesting across multiple distinct customer resources.
     */
    EXCESSIVE_DATA_EXTRACTION("Excessive Data Extraction"),

    /**
     * Cumulative extraction across extended time windows where individual requests remain below rapid thresholds.
     */
    LOW_AND_SLOW_EXTRACTION("Low-and-Slow Extraction"),

    /**
     * Coordinated extraction distributed across related sessions or identities.
     */
    DISTRIBUTED_EXTRACTION("Distributed Extraction"),

    /**
     * Automated harvesting exploiting pagination and cursor progression.
     */
    PAGINATION_EXTRACTION("Pagination-Based Extraction"),

    /**
     * Correlated cross-resource extraction spanning customer, account, and transaction domains.
     */
    MULTI_RESOURCE_EXTRACTION("Multi-Resource Extraction"),

    /**
     * Correlated multi-stage exfiltration sequence (enumeration -> BOLA attempts -> sensitive extraction).
     */
    DATA_EXFILTRATION_CAMPAIGN("Data Exfiltration Campaign");

    private final String displayName;

    DataLeakageCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}

