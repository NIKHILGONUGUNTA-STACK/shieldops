package com.aegis.gateway.websocket;

import com.aegis.gateway.websocket.dto.SocRealtimeNotification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class WebSocketSecurityEventPublisherTest {

    private SimpMessagingTemplate messagingTemplate;
    private WebSocketSecurityEventPublisher publisher;

    @BeforeEach
    void setUp() {
        messagingTemplate = mock(SimpMessagingTemplate.class);
        publisher = new WebSocketSecurityEventPublisher(messagingTemplate);
    }

    @Test
    @DisplayName("publishNotification sends alert to /topic/notifications")
    void testPublishNotification() {
        SocRealtimeNotification notification = new SocRealtimeNotification(
            UUID.randomUUID().toString(),
            "INCIDENT_ALERT",
            "Critical BOLA Alert",
            "Cross-tenant IDOR access detected",
            "CRITICAL",
            "inc-100",
            "INCIDENT",
            Instant.now()
        );

        publisher.publishNotification(notification);

        verify(messagingTemplate).convertAndSend(eq("/topic/notifications"), eq(notification));
    }

    @Test
    @DisplayName("publishIncidentUpdate broadcasts to /topic/incidents and notifies analysts")
    void testPublishIncidentUpdate() {
        String incidentPayload = "INC-BOLA-2026-001";

        publisher.publishIncidentUpdate(incidentPayload, "STATUS_INVESTIGATING", "Analyst assigned");

        verify(messagingTemplate).convertAndSend(eq("/topic/incidents"), eq(incidentPayload));
        verify(messagingTemplate).convertAndSend(eq("/topic/notifications"), any(SocRealtimeNotification.class));
    }

    @Test
    @DisplayName("publishCampaignEscalation broadcasts to /topic/campaigns and emits critical alert")
    void testPublishCampaignEscalation() {
        publisher.publishCampaignEscalation("EXFIL-001", "EXFIL-CAMPAIGN-001", "BULK_EXTRACTION");

        verify(messagingTemplate).convertAndSend(eq("/topic/campaigns"), eq("EXFIL-001"));
        ArgumentCaptor<SocRealtimeNotification> captor = ArgumentCaptor.forClass(SocRealtimeNotification.class);
        verify(messagingTemplate).convertAndSend(eq("/topic/notifications"), captor.capture());

        SocRealtimeNotification notification = captor.getValue();
        assertThat(notification.severity()).isEqualTo("CRITICAL");
        assertThat(notification.type()).isEqualTo("CAMPAIGN_ESCALATION");
    }

    @Test
    @DisplayName("publishTelemetryBurst broadcasts batch summary to /topic/telemetry")
    void testPublishTelemetryBurst() {
        publisher.publishTelemetryBurst(50, "MIXED");

        verify(messagingTemplate).convertAndSend(eq("/topic/telemetry"), any(Map.class));
        verify(messagingTemplate).convertAndSend(eq("/topic/notifications"), any(SocRealtimeNotification.class));
    }

    @Test
    @DisplayName("Null messagingTemplate safely degrades without throwing exception")
    void testNullMessagingTemplateSafety() {
        WebSocketSecurityEventPublisher nullPublisher = new WebSocketSecurityEventPublisher(null);

        // Should not throw NPE
        nullPublisher.publishNotification(new SocRealtimeNotification(
            "1", "TEST", "T", "M", "INFO", "e1", "SYS", Instant.now()
        ));
        nullPublisher.publishIncidentUpdate("inc-1", "OPEN", "reason");
        nullPublisher.publishTelemetryBurst(10, "BENIGN");
    }
}
