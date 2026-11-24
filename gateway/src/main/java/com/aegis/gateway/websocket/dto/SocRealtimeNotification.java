package com.aegis.gateway.websocket.dto;

import java.time.Instant;

/**
 * Real-time alert payload delivered over STOMP WebSocket topics to active SOC analyst sessions.
 */
public record SocRealtimeNotification(
    String id,
    String type,        // "INCIDENT_ALERT", "CAMPAIGN_ESCALATION", "POLICY_ADVISORY", "BURST_INGESTION", "SYSTEM_HEALTH"
    String title,
    String message,
    String severity,    // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    String entityId,
    String entityType,  // "INCIDENT", "CAMPAIGN", "POLICY", "SIMULATION", "SYSTEM"
    Instant timestamp
) {}
