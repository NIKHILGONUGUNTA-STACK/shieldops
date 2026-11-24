package com.aegis.gateway.websocket;

import com.aegis.gateway.websocket.dto.SocRealtimeNotification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.messaging.converter.MappingJackson2MessageConverter;
import org.springframework.messaging.simp.stomp.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.messaging.WebSocketStompClient;

import java.lang.reflect.Type;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "aegis.seed.baseline.enabled=false"
})
@ActiveProfiles("test")
class WebSocketIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private WebSocketSecurityEventPublisher eventPublisher;

    @Test
    @DisplayName("STOMP client connects to /ws/soc-feed-raw, subscribes to /topic/notifications, and receives live broadcast")
    void testLiveWebSocketStompPubSub() throws Exception {
        WebSocketStompClient stompClient = new WebSocketStompClient(new StandardWebSocketClient());
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        mapper.disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        MappingJackson2MessageConverter converter = new MappingJackson2MessageConverter();
        converter.setObjectMapper(mapper);
        stompClient.setMessageConverter(converter);

        String wsUrl = "ws://localhost:" + port + "/ws/soc-feed-raw";
        CompletableFuture<SocRealtimeNotification> receivedFuture = new CompletableFuture<>();

        StompSession session = stompClient.connectAsync(wsUrl, new StompSessionHandlerAdapter() {
            @Override
            public void handleException(StompSession session, StompCommand command, StompHeaders headers, byte[] payload, Throwable exception) {
                receivedFuture.completeExceptionally(exception);
            }
        }).get(5, TimeUnit.SECONDS);

        assertThat(session.isConnected()).isTrue();

        // Subscribe to real-time notification topic
        session.subscribe("/topic/notifications", new StompFrameHandler() {
            @Override
            public Type getPayloadType(StompHeaders headers) {
                return SocRealtimeNotification.class;
            }

            @Override
            public void handleFrame(StompHeaders headers, Object payload) {
                receivedFuture.complete((SocRealtimeNotification) payload);
            }
        });

        // Allow broker subscription registration
        Thread.sleep(200);

        // Publish live event
        String testId = UUID.randomUUID().toString();
        SocRealtimeNotification notification = new SocRealtimeNotification(
            testId,
            "INCIDENT_ALERT",
            "Real-Time Integration Alert",
            "Validated live STOMP frame delivery",
            "HIGH",
            "ent-101",
            "INCIDENT",
            Instant.now()
        );

        eventPublisher.publishNotification(notification);

        // Await delivery
        SocRealtimeNotification received = receivedFuture.get(5, TimeUnit.SECONDS);

        assertThat(received).isNotNull();
        assertThat(received.id()).isEqualTo(testId);
        assertThat(received.title()).isEqualTo("Real-Time Integration Alert");
        assertThat(received.severity()).isEqualTo("HIGH");

        session.disconnect();
    }
}
