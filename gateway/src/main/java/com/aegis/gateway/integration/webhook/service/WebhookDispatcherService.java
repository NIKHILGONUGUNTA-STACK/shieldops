package com.aegis.gateway.integration.webhook.service;

import com.aegis.gateway.integration.webhook.dto.*;
import com.aegis.gateway.integration.webhook.model.WebhookEventType;
import com.aegis.gateway.integration.webhook.model.WebhookSubscription;
import com.aegis.gateway.integration.webhook.repository.WebhookRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Enterprise asynchronous outbound webhook dispatching engine.
 * Ensures non-blocking execution with HMAC-SHA256 signature verification.
 */
@Service
public class WebhookDispatcherService {

    private static final Logger log = LoggerFactory.getLogger(WebhookDispatcherService.class);

    private final WebhookRepository webhookRepository;
    private final WebhookSignatureService signatureService;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final ExecutorService executorService;

    public WebhookDispatcherService(
            WebhookRepository webhookRepository,
            WebhookSignatureService signatureService,
            ObjectMapper objectMapper) {
        this.webhookRepository = webhookRepository;
        this.signatureService = signatureService;
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .build();
        this.executorService = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "aegis-webhook-dispatcher");
            t.setDaemon(true);
            return t;
        });
    }

    public List<WebhookSubscription> getAllSubscriptions(String tenantId) {
        return webhookRepository.findByTenantId(tenantId);
    }

    public Optional<WebhookSubscription> getSubscription(String id) {
        return webhookRepository.findById(id);
    }

    public WebhookSubscription createSubscription(WebhookSubscriptionCreateRequest request) {
        String id = "sub-" + UUID.randomUUID().toString().substring(0, 8);
        String secret = (request.secretToken() != null && !request.secretToken().isBlank())
            ? request.secretToken().trim()
            : UUID.randomUUID().toString().replace("-", "");

        WebhookSubscription subscription = new WebhookSubscription(
            id,
            request.tenantId() != null && !request.tenantId().isBlank() ? request.tenantId().trim() : "tenant-fintech-us",
            request.name().trim(),
            request.targetUrl().trim(),
            secret,
            request.eventTypes(),
            true,
            Instant.now(),
            null,
            null,
            0,
            0
        );
        log.info("Created new webhook subscription: id={}, name={}, targetUrl={}", id, subscription.name(), subscription.targetUrl());
        return webhookRepository.save(subscription);
    }

    public boolean deleteSubscription(String id) {
        return webhookRepository.deleteById(id);
    }

    /**
     * Out-of-band asynchronous dispatch for security incident events.
     */
    public void dispatchIncidentEvent(
            String tenantId,
            String incidentId,
            String severity,
            String title,
            String summary,
            WebhookEventType eventType,
            Map<String, Object> extra) {

        CompletableFuture.runAsync(() -> {
            try {
                List<WebhookSubscription> subscriptions = webhookRepository.findAll();
                WebhookPayload payload = new WebhookPayload(
                    UUID.randomUUID().toString(),
                    eventType,
                    Instant.now(),
                    tenantId != null ? tenantId : "tenant-fintech-us",
                    severity,
                    title,
                    summary,
                    extra != null ? extra : Map.of("incidentId", incidentId)
                );

                for (WebhookSubscription sub : subscriptions) {
                    if (!sub.enabled()) continue;
                    boolean tenantMatch = sub.tenantId() == null
                        || "ALL".equalsIgnoreCase(sub.tenantId())
                        || sub.tenantId().equalsIgnoreCase(tenantId);

                    boolean eventMatch = sub.eventTypes().contains(eventType)
                        || sub.eventTypes().contains(WebhookEventType.INCIDENT_CRITICAL) && "CRITICAL".equalsIgnoreCase(severity);

                    if (tenantMatch && eventMatch) {
                        deliverPayload(sub, payload);
                    }
                }
            } catch (Exception e) {
                log.error("Error in background incident webhook dispatch: {}", e.getMessage(), e);
            }
        }, executorService);
    }

    /**
     * Executes test delivery against an existing subscription.
     */
    public WebhookDispatchResult triggerSubscriptionTest(String subscriptionId) {
        WebhookSubscription sub = webhookRepository.findById(subscriptionId)
            .orElseThrow(() -> new IllegalArgumentException("Webhook subscription not found: " + subscriptionId));

        WebhookPayload testPayload = new WebhookPayload(
            UUID.randomUUID().toString(),
            WebhookEventType.TEST_PING,
            Instant.now(),
            sub.tenantId(),
            "INFO",
            "Aegis ShieldOps Webhook Verification Ping",
            "Diagnostic test payload verifying webhook connectivity and HMAC-SHA256 signature verification.",
            Map.of("subscriptionId", sub.id(), "testTimestamp", Instant.now().toString())
        );

        return executeDelivery(sub.id(), sub.targetUrl(), sub.secretToken(), testPayload);
    }

    /**
     * Executes test delivery against an ad-hoc target URL and secret.
     */
    public WebhookDispatchResult testDispatch(String targetUrl, String secretToken, String message) {
        WebhookPayload payload = new WebhookPayload(
            UUID.randomUUID().toString(),
            WebhookEventType.TEST_PING,
            Instant.now(),
            "tenant-fintech-us",
            "INFO",
            "Aegis Diagnostic Test Ping",
            message != null && !message.isBlank() ? message : "ShieldOps webhook connectivity verification",
            Map.of("source", "aegis-admin-test", "timestamp", Instant.now().toString())
        );

        return executeDelivery("adhoc-test", targetUrl, secretToken, payload);
    }

    private void deliverPayload(WebhookSubscription sub, WebhookPayload payload) {
        WebhookDispatchResult result = executeDelivery(sub.id(), sub.targetUrl(), sub.secretToken(), payload);
        WebhookSubscription updated = sub.withTriggerResult(result.statusCode(), result.success());
        webhookRepository.save(updated);
    }

    private WebhookDispatchResult executeDelivery(String subId, String targetUrl, String secret, WebhookPayload payload) {
        long start = System.currentTimeMillis();
        try {
            String json = objectMapper.writeValueAsString(payload);
            String signature = signatureService.calculateSignature(json, secret);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Aegis-ShieldOps-Webhook/1.0")
                .header("X-Aegis-Event", payload.eventType().name())
                .header("X-Aegis-Delivery", payload.eventId())
                .header("X-Aegis-Timestamp", payload.timestamp().toString())
                .header("X-Aegis-Signature", signature)
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long latency = System.currentTimeMillis() - start;
            boolean success = response.statusCode() >= 200 && response.statusCode() < 300;

            log.info("Webhook delivered: target={}, status={}, latencyMs={}", targetUrl, response.statusCode(), latency);
            return new WebhookDispatchResult(
                subId, targetUrl, response.statusCode(), success,
                success ? "Delivered successfully" : "HTTP Status " + response.statusCode(),
                latency, Instant.now()
            );
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            log.warn("Webhook delivery failed for target {}: {}", targetUrl, e.getMessage());
            return new WebhookDispatchResult(
                subId, targetUrl, 503, false,
                "Delivery failed: " + e.getMessage(), latency, Instant.now()
            );
        }
    }
}
