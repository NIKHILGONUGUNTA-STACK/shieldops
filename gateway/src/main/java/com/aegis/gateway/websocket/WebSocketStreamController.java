package com.aegis.gateway.websocket;

import com.aegis.gateway.websocket.dto.SocRealtimeNotification;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Controller for managing and testing real-time WebSocket streaming in the SOC.
 */
@RestController
@RequestMapping("/api/v1/soc/ws")
public class WebSocketStreamController {

    private final WebSocketSecurityEventPublisher eventPublisher;

    public WebSocketStreamController(WebSocketSecurityEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    /**
     * Returns the active WebSocket broker capabilities and supported subscription topics.
     */
    @GetMapping("/status")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<Map<String, Object>> getWebSocketStatus() {
        return ResponseEntity.ok(Map.of(
            "status", "ACTIVE",
            "protocol", "STOMP_OVER_WEBSOCKET",
            "endpoints", List.of("/ws/soc-feed", "/ws/soc-feed-raw"),
            "topics", List.of(
                WebSocketSecurityEventPublisher.TOPIC_NOTIFICATIONS,
                WebSocketSecurityEventPublisher.TOPIC_INCIDENTS,
                WebSocketSecurityEventPublisher.TOPIC_CAMPAIGNS,
                WebSocketSecurityEventPublisher.TOPIC_POLICIES,
                WebSocketSecurityEventPublisher.TOPIC_TELEMETRY
            ),
            "timestamp", Instant.now().toString()
        ));
    }

    /**
     * Broadcasts a test alert notification over STOMP to verify live end-to-end client connectivity.
     */
    @PostMapping("/broadcast-test")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<SocRealtimeNotification> broadcastTestNotification(
        @RequestParam(name = "title", defaultValue = "SOC Real-Time Stream Heartbeat") String title,
        @RequestParam(name = "severity", defaultValue = "INFO") String severity,
        @RequestParam(name = "message", defaultValue = "Live WebSocket STOMP channel is active and streaming.") String message
    ) {
        SocRealtimeNotification notification = new SocRealtimeNotification(
            UUID.randomUUID().toString(),
            "SYSTEM_HEALTH",
            title,
            message,
            severity,
            "system-ws-broadcast",
            "SYSTEM",
            Instant.now()
        );

        eventPublisher.publishNotification(notification);
        return ResponseEntity.ok(notification);
    }
}
