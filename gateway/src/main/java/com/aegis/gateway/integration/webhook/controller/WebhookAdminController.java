package com.aegis.gateway.integration.webhook.controller;

import com.aegis.gateway.integration.webhook.dto.*;
import com.aegis.gateway.integration.webhook.model.WebhookSubscription;
import com.aegis.gateway.integration.webhook.service.WebhookDispatcherService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

/**
 * REST controller for third-party webhook alert management and diagnostic testing.
 */
@RestController
@RequestMapping("/api/v1/admin/webhooks")
public class WebhookAdminController {

    private static final Logger log = LoggerFactory.getLogger(WebhookAdminController.class);

    private final WebhookDispatcherService webhookDispatcherService;

    public WebhookAdminController(WebhookDispatcherService webhookDispatcherService) {
        this.webhookDispatcherService = webhookDispatcherService;
    }

    /**
     * GET /api/v1/admin/webhooks
     * List all registered webhook subscriptions.
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<WebhookSubscription>> getSubscriptions(
            @RequestParam(name = "tenantId", required = false) String tenantId) {
        return ResponseEntity.ok(webhookDispatcherService.getAllSubscriptions(tenantId));
    }

    /**
     * GET /api/v1/admin/webhooks/{id}
     * Get specific webhook subscription.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> getSubscription(@PathVariable("id") String id) {
        return webhookDispatcherService.getSubscription(id)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElseGet(() -> {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Webhook subscription not found: " + id
                );
                problem.setTitle("Webhook Subscription Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/webhook-not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            });
    }

    /**
     * POST /api/v1/admin/webhooks
     * Register a new webhook subscription.
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<WebhookSubscription> createSubscription(
            @Valid @RequestBody WebhookSubscriptionCreateRequest request) {
        WebhookSubscription created = webhookDispatcherService.createSubscription(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * DELETE /api/v1/admin/webhooks/{id}
     * Remove a webhook subscription.
     */
    @DeleteMapping(value = "/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<Void> deleteSubscription(@PathVariable("id") String id) {
        boolean deleted = webhookDispatcherService.deleteSubscription(id);
        if (deleted) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * POST /api/v1/admin/webhooks/{id}/test
     * Trigger a test dispatch against a specific subscription.
     */
    @PostMapping(value = "/{id}/test", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> triggerTest(@PathVariable("id") String id) {
        try {
            WebhookDispatchResult result = webhookDispatcherService.triggerSubscriptionTest(id);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException iae) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, iae.getMessage());
            problem.setTitle("Webhook Subscription Not Found");
            problem.setType(URI.create("https://aegis.dev/errors/webhook-not-found"));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
        }
    }

    /**
     * POST /api/v1/admin/webhooks/test-dispatch
     * Ad-hoc test delivery to an external webhook URL.
     */
    @PostMapping(value = "/test-dispatch", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<WebhookDispatchResult> testDispatch(
            @Valid @RequestBody WebhookTestDispatchRequest request) {
        WebhookDispatchResult result = webhookDispatcherService.testDispatch(
            request.targetUrl(), request.secretToken(), request.message()
        );
        return ResponseEntity.ok(result);
    }
}
