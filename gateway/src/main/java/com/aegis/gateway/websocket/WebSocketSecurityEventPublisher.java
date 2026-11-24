package com.aegis.gateway.websocket;

import com.aegis.gateway.websocket.dto.SocRealtimeNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Out-of-band real-time security event publisher.
 * Broadcasts events, incidents, campaigns, and advisory policy recommendations over STOMP topics.
 */
@Component
public class WebSocketSecurityEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(WebSocketSecurityEventPublisher.class);

    public static final String TOPIC_NOTIFICATIONS = "/topic/notifications";
    public static final String TOPIC_INCIDENTS = "/topic/incidents";
    public static final String TOPIC_CAMPAIGNS = "/topic/campaigns";
    public static final String TOPIC_POLICIES = "/topic/policies";
    public static final String TOPIC_TELEMETRY = "/topic/telemetry";

    private final SimpMessagingTemplate messagingTemplate;

    @Autowired
    public WebSocketSecurityEventPublisher(@Autowired(required = false) SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }

    /**
     * Broadcasts a real-time toast alert notification to all active SOC sessions.
     */
    public void publishNotification(SocRealtimeNotification notification) {
        if (messagingTemplate == null) {
            log.debug("SimpMessagingTemplate not available; skipping WebSocket notification: {}", notification.title());
            return;
        }
        try {
            messagingTemplate.convertAndSend(TOPIC_NOTIFICATIONS, notification);
            log.debug("Broadcasted SOC notification [{}] to {}", notification.type(), TOPIC_NOTIFICATIONS);
        } catch (Exception e) {
            log.warn("Failed to broadcast WebSocket notification: {}", e.getMessage());
        }
    }

    /**
     * Broadcasts an incident state update or new alert to /topic/incidents.
     */
    public void publishIncidentUpdate(Object incident, String action, String rationale) {
        if (messagingTemplate == null) return;
        try {
            messagingTemplate.convertAndSend(TOPIC_INCIDENTS, incident);
            publishNotification(new SocRealtimeNotification(
                UUID.randomUUID().toString(),
                "INCIDENT_ALERT",
                "Incident " + action,
                rationale != null ? rationale : "Security incident status updated",
                "HIGH",
                incident.toString(),
                "INCIDENT",
                Instant.now()
            ));
        } catch (Exception e) {
            log.warn("Failed to publish incident update to WebSocket: {}", e.getMessage());
        }
    }

    /**
     * Broadcasts a multi-stage exfiltration campaign escalation to /topic/campaigns.
     */
    public void publishCampaignEscalation(Object campaign, String campaignId, String stage) {
        if (messagingTemplate == null) return;
        try {
            messagingTemplate.convertAndSend(TOPIC_CAMPAIGNS, campaign);
            publishNotification(new SocRealtimeNotification(
                UUID.randomUUID().toString(),
                "CAMPAIGN_ESCALATION",
                "Campaign Escalation: " + campaignId,
                "Adversary advanced to stage: " + stage,
                "CRITICAL",
                campaignId,
                "CAMPAIGN",
                Instant.now()
            ));
        } catch (Exception e) {
            log.warn("Failed to publish campaign update to WebSocket: {}", e.getMessage());
        }
    }

    /**
     * Broadcasts an adaptive policy decision to /topic/policies.
     */
    public void publishPolicyDecision(Object decision, String policyId, String action) {
        if (messagingTemplate == null) return;
        try {
            messagingTemplate.convertAndSend(TOPIC_POLICIES, decision);
            publishNotification(new SocRealtimeNotification(
                UUID.randomUUID().toString(),
                "POLICY_ADVISORY",
                "Policy Advisory: " + policyId,
                "Recommended Action: " + action + " (Strictly Advisory)",
                "INFO",
                policyId,
                "POLICY",
                Instant.now()
            ));
        } catch (Exception e) {
            log.warn("Failed to publish policy decision to WebSocket: {}", e.getMessage());
        }
    }

    /**
     * Broadcasts live telemetry ingestion bursts to /topic/telemetry.
     */
    public void publishTelemetryBurst(int eventCount, String profile) {
        if (messagingTemplate == null) return;
        try {
            messagingTemplate.convertAndSend(TOPIC_TELEMETRY, java.util.Map.of(
                "eventCount", eventCount,
                "profile", profile,
                "timestamp", Instant.now().toString()
            ));
            publishNotification(new SocRealtimeNotification(
                UUID.randomUUID().toString(),
                "BURST_INGESTION",
                "Live Telemetry Ingested",
                "Ingested on-demand burst of " + eventCount + " " + profile + " events",
                "INFO",
                UUID.randomUUID().toString(),
                "SIMULATION",
                Instant.now()
            ));
        } catch (Exception e) {
            log.warn("Failed to publish telemetry burst to WebSocket: {}", e.getMessage());
        }
    }
}
