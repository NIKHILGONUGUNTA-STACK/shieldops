package com.aegis.gateway.websocket;

import com.aegis.gateway.websocket.dto.SocRealtimeNotification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class WebSocketStreamControllerTest {

    private WebSocketSecurityEventPublisher eventPublisher;
    private WebSocketStreamController controller;

    @BeforeEach
    void setUp() {
        eventPublisher = mock(WebSocketSecurityEventPublisher.class);
        controller = new WebSocketStreamController(eventPublisher);
    }

    @Test
    @DisplayName("getWebSocketStatus returns active endpoints and topics")
    void testGetWebSocketStatus() {
        ResponseEntity<Map<String, Object>> response = controller.getWebSocketStatus();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("status")).isEqualTo("ACTIVE");
        assertThat(body.get("protocol")).isEqualTo("STOMP_OVER_WEBSOCKET");
        assertThat(body.get("topics").toString()).contains("/topic/notifications");
    }

    @Test
    @DisplayName("broadcastTestNotification triggers publication to broker")
    void testBroadcastTestNotification() {
        ResponseEntity<SocRealtimeNotification> response = controller.broadcastTestNotification(
            "Test Alert", "HIGH", "Simulated intrusion alert"
        );

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        SocRealtimeNotification body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.title()).isEqualTo("Test Alert");
        assertThat(body.severity()).isEqualTo("HIGH");

        verify(eventPublisher).publishNotification(any(SocRealtimeNotification.class));
    }
}
