package com.aegis.gateway.soar;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.*;

/**
 * REST API exposing Autonomous SOAR, Dynamic WAF, Token Revocation, and Challenge Gate controls.
 */
@RestController
@RequestMapping("/api/v1/security/soar")
public class SoarController {

    private final DynamicWafService wafService;
    private final TokenRevocationService tokenRevocationService;
    private final SoarTicketingService ticketingService;
    private final AdaptiveChallengeService challengeService;

    @Autowired
    public SoarController(
            DynamicWafService wafService,
            TokenRevocationService tokenRevocationService,
            SoarTicketingService ticketingService,
            AdaptiveChallengeService challengeService) {
        this.wafService = wafService;
        this.tokenRevocationService = tokenRevocationService;
        this.ticketingService = ticketingService;
        this.challengeService = challengeService;
    }

    // ------------------------------------------------------------------------
    // Dynamic WAF & Edge Null-Routing
    // ------------------------------------------------------------------------

    @GetMapping("/waf/rules")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<WafBanRule>> getWafRules() {
        return ResponseEntity.ok(wafService.getActiveBans());
    }

    public record BanRequest(String ipOrCidr, String reason, String incidentId, Integer ttlHours, String source) {}

    @PostMapping("/waf/ban")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<WafBanRule> addBan(@RequestBody BanRequest request) {
        Duration ttl = request.ttlHours() != null ? Duration.ofHours(request.ttlHours()) : Duration.ofDays(1);
        WafBanRule rule = wafService.addBan(request.ipOrCidr(), request.reason(), request.incidentId(), ttl, request.source());
        return ResponseEntity.status(HttpStatus.CREATED).body(rule);
    }

    @DeleteMapping("/waf/ban/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<Void> removeBan(@PathVariable String id) {
        boolean removed = wafService.removeBan(id);
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/waf/export/cloudflare")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Map<String, Object>> exportCloudflare() {
        return ResponseEntity.ok(wafService.toCloudflarePayload());
    }

    @GetMapping("/waf/export/aws")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Map<String, Object>> exportAwsWaf() {
        return ResponseEntity.ok(wafService.toAwsWafIpSet());
    }

    @GetMapping("/waf/export/iptables")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<String>> exportIptables() {
        return ResponseEntity.ok(wafService.toIptablesRules());
    }

    // ------------------------------------------------------------------------
    // Cryptographic Token Revocation
    // ------------------------------------------------------------------------

    @GetMapping("/tokens/revoked")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<TokenRevocationRecord>> getRevokedTokens() {
        return ResponseEntity.ok(tokenRevocationService.getRevokedTokens());
    }

    public record TokenRevokeRequest(String jti, String subject, String reason, Integer ttlHours) {}

    @PostMapping("/tokens/revoke")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<TokenRevocationRecord> revokeToken(@RequestBody TokenRevokeRequest request) {
        Duration ttl = request.ttlHours() != null ? Duration.ofHours(request.ttlHours()) : Duration.ofHours(24);
        TokenRevocationRecord record = tokenRevocationService.revokeToken(request.jti(), request.subject(), request.reason(), ttl);
        return ResponseEntity.status(HttpStatus.CREATED).body(record);
    }

    public record SubjectRevokeRequest(String subject, String reason, Integer retentionHours) {}

    @PostMapping("/tokens/revoke-subject")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<Void> revokeSubject(@RequestBody SubjectRevokeRequest request) {
        Duration retention = request.retentionHours() != null ? Duration.ofHours(request.retentionHours()) : Duration.ofHours(24);
        tokenRevocationService.revokeSubject(request.subject(), request.reason(), retention);
        return ResponseEntity.noContent().build();
    }

    // ------------------------------------------------------------------------
    // Bidirectional SOAR Ticketing
    // ------------------------------------------------------------------------

    @GetMapping("/tickets")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<SoarTicket>> getTickets() {
        return ResponseEntity.ok(ticketingService.getTickets());
    }

    public record CreateTicketRequest(String incidentId, String externalSystem, String title, String severity, String assignee) {}

    @PostMapping("/tickets")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<SoarTicket> createTicket(@RequestBody CreateTicketRequest request) {
        SoarTicket ticket = ticketingService.createTicket(
                request.incidentId(),
                request.externalSystem(),
                request.title(),
                request.severity(),
                request.assignee()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(ticket);
    }

    public record WebhookCallbackRequest(String externalTicketId, String status, String comment) {}

    @PostMapping("/tickets/callback")
    public ResponseEntity<SoarTicket> handleTicketCallback(@RequestBody WebhookCallbackRequest request) {
        Optional<SoarTicket> updated = ticketingService.handleCallback(
                request.externalTicketId(),
                request.status(),
                request.comment()
        );
        return updated.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    // ------------------------------------------------------------------------
    // Adaptive Step-Up Challenge Gate
    // ------------------------------------------------------------------------

    public record IssueChallengeRequest(String sessionId, String reason, Double threatRisk) {}

    @PostMapping("/challenge/issue")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<AdaptiveChallengeService.ChallengeSession> issueChallenge(@RequestBody IssueChallengeRequest request) {
        double risk = request.threatRisk() != null ? request.threatRisk() : 0.75;
        AdaptiveChallengeService.ChallengeSession session = challengeService.issueChallenge(request.sessionId(), request.reason(), risk);
        return ResponseEntity.status(HttpStatus.CREATED).body(session);
    }

    public record VerifyChallengeRequest(String sessionId, String responseToken) {}

    @PostMapping("/challenge/verify")
    public ResponseEntity<Map<String, Object>> verifyChallenge(@RequestBody VerifyChallengeRequest request) {
        boolean verified = challengeService.verifyChallenge(request.sessionId(), request.responseToken());
        return ResponseEntity.ok(Map.of(
                "sessionId", request.sessionId(),
                "verified", verified,
                "status", verified ? "CLEARED" : "CHALLENGE_FAILED"
        ));
    }

    @GetMapping("/challenge/status/{sessionId}")
    public ResponseEntity<Map<String, Object>> getChallengeStatus(@PathVariable String sessionId) {
        boolean cleared = challengeService.isCleared(sessionId);
        Optional<AdaptiveChallengeService.ChallengeSession> session = challengeService.getSession(sessionId);

        return ResponseEntity.ok(Map.of(
                "sessionId", sessionId,
                "cleared", cleared,
                "session", session.orElse(null)
        ));
    }

    @GetMapping("/challenge/metrics")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Map<String, Object>> getChallengeMetrics() {
        return ResponseEntity.ok(challengeService.getMetrics());
    }
}
