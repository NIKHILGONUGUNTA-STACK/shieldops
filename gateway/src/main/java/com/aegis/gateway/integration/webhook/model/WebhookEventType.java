package com.aegis.gateway.integration.webhook.model;

/**
 * Event types dispatched to third-party webhook integrations.
 */
public enum WebhookEventType {
    INCIDENT_CREATED,
    INCIDENT_STATUS_CHANGED,
    INCIDENT_CRITICAL,
    CAMPAIGN_ESCALATED,
    POLICY_ADVISORY_TRIGGERED,
    TEST_PING
}
