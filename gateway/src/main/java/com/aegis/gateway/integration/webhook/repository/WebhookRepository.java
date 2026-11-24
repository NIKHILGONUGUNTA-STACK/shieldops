package com.aegis.gateway.integration.webhook.repository;

import com.aegis.gateway.integration.webhook.model.WebhookEventType;
import com.aegis.gateway.integration.webhook.model.WebhookSubscription;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise thread-safe registry repository for Webhook Subscriptions.
 */
@Repository
public class WebhookRepository {

    private final Map<String, WebhookSubscription> subscriptions = new ConcurrentHashMap<>();

    public WebhookRepository() {
        seedDefaultSubscriptions();
    }

    private void seedDefaultSubscriptions() {
        Instant now = Instant.now();

        save(new WebhookSubscription(
            "sub-slack-fintech-us",
            "tenant-fintech-us",
            "Enterprise SOC Slack Channel",
            "https://hooks.slack.com/services/T00/B00/secops",
            "secret_token_slack_fintech_2026",
            List.of(WebhookEventType.INCIDENT_CRITICAL, WebhookEventType.CAMPAIGN_ESCALATED),
            true,
            now.minusSeconds(86400 * 15),
            now.minusSeconds(3600),
            200,
            42,
            0
        ));

        save(new WebhookSubscription(
            "sub-pagerduty-banking-eu",
            "tenant-banking-eu",
            "Apex Bank PagerDuty High-Sev Ingestion",
            "https://events.pagerduty.com/v2/enqueue",
            "secret_token_pd_banking_2026",
            List.of(WebhookEventType.INCIDENT_CRITICAL, WebhookEventType.INCIDENT_STATUS_CHANGED),
            true,
            now.minusSeconds(86400 * 10),
            now.minusSeconds(7200),
            202,
            18,
            0
        ));
    }

    public List<WebhookSubscription> findAll() {
        return new ArrayList<>(subscriptions.values());
    }

    public Optional<WebhookSubscription> findById(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(subscriptions.get(id.trim()));
    }

    public List<WebhookSubscription> findByTenantId(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) return findAll();
        return subscriptions.values().stream()
            .filter(s -> s.tenantId() == null || s.tenantId().equalsIgnoreCase(tenantId.trim()) || "ALL".equalsIgnoreCase(s.tenantId()))
            .toList();
    }

    public WebhookSubscription save(WebhookSubscription subscription) {
        if (subscription == null || subscription.id() == null) {
            throw new IllegalArgumentException("Webhook subscription and id must not be null");
        }
        subscriptions.put(subscription.id().trim(), subscription);
        return subscription;
    }

    public boolean deleteById(String id) {
        if (id == null) return false;
        return subscriptions.remove(id.trim()) != null;
    }

    public long count() {
        return subscriptions.size();
    }
}
