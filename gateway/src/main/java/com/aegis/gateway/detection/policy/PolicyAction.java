package com.aegis.gateway.detection.policy;

/**
 * Structured security response recommendations.
 * Strictly non-enforcing in Phase 7.2.4.6 (advisory only).
 */
public enum PolicyAction {
    MONITOR_ACTIVITY,
    INVESTIGATE_ACTIVITY,
    REVIEW_AUTHORIZATION,
    REVIEW_DATA_EXPOSURE,
    ESCALATE_INCIDENT,
    PRIORITIZE_CAMPAIGN,
    REQUEST_ADDITIONAL_EVIDENCE,
    LOG_ALERT
}
