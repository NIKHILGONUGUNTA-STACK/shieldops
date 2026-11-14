package com.aegis.gateway.detection.policy;

/**
 * Domain category for adaptive security response policies.
 */
public enum PolicyCategory {
    RECONNAISSANCE,
    AUTHORIZATION,
    DATA_EXPOSURE,
    BULK_EXTRACTION,
    CAMPAIGN,
    EVIDENCE_INTEGRITY,
    GENERAL
}
