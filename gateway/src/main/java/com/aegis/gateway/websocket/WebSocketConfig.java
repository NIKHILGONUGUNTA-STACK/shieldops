package com.aegis.gateway.websocket;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Spring STOMP over WebSocket configuration for real-time Aegis SOC telemetry and live alert streaming.
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Enable in-memory simple broker for real-time pub/sub topics
        config.enableSimpleBroker("/topic", "/queue");
        // Application destination prefix for client-to-server messages
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Primary endpoint with SockJS fallback for browser compatibility
        registry.addEndpoint("/ws/soc-feed")
                .setAllowedOriginPatterns("*")
                .withSockJS();

        // Raw WebSocket endpoint for native clients, proxies, and CLI tools
        registry.addEndpoint("/ws/soc-feed-raw")
                .setAllowedOriginPatterns("*");
    }
}
