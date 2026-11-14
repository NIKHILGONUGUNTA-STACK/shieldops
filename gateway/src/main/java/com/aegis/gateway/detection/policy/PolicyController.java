package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignRepository;
import com.aegis.gateway.detection.campaign.ExfiltrationCampaign;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.policy.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/security")
@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
public class PolicyController {

    private final PolicyRepository policyRepository;
    private final AdaptivePolicyEngine policyEngine;
    private final IncidentRepository incidentRepository;
    private final CampaignRepository campaignRepository;

    public PolicyController(
        PolicyRepository policyRepository,
        AdaptivePolicyEngine policyEngine,
        IncidentRepository incidentRepository,
        CampaignRepository campaignRepository
    ) {
        this.policyRepository = policyRepository;
        this.policyEngine = policyEngine;
        this.incidentRepository = incidentRepository;
        this.campaignRepository = campaignRepository;
    }

    // =========================================================================
    // 1. Policy Registry Endpoints (/policies)
    // =========================================================================

    @GetMapping("/policies")
    public ResponseEntity<List<SecurityPolicyResponse>> getAllPolicies() {
        List<SecurityPolicyResponse> policies = policyRepository.findAllPolicies().stream()
            .map(SecurityPolicyResponse::from)
            .toList();
        return ResponseEntity.ok(policies);
    }

    @GetMapping("/policies/{id}")
    public ResponseEntity<SecurityPolicyResponse> getPolicyById(@PathVariable("id") String id) {
        SecurityPolicy policy = policyRepository.findPolicyById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy not found: " + id));
        return ResponseEntity.ok(SecurityPolicyResponse.from(policy));
    }

    @PutMapping("/policies/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<SecurityPolicyResponse> updatePolicy(
        @PathVariable("id") String id,
        @Valid @RequestBody PolicyUpdateRequest req
    ) {
        SecurityPolicy current = policyRepository.findPolicyById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy not found: " + id));

        String username = resolveCurrentUsername();
        String prevVersion = current.version();

        // Increment minor version: e.g. 1.0.0 -> 1.1.0
        String[] parts = prevVersion.split("\\.");
        int minor = parts.length > 1 ? Integer.parseInt(parts[1]) + 1 : 1;
        String newVersion = parts[0] + "." + minor + ".0";

        SecurityPolicy updated = new SecurityPolicy(
            current.id(),
            current.name(),
            newVersion,
            current.category(),
            current.recommendedAction(),
            req.description() != null ? req.description() : current.description(),
            req.enabled() != null ? req.enabled() : current.enabled(),
            req.riskThreshold() != null ? req.riskThreshold() : current.riskThreshold(),
            current.conditionExplanation(),
            current.effectiveFrom(),
            Instant.now()
        );

        policyRepository.updatePolicy(updated);

        // Record audit history
        PolicyAuditHistory audit = new PolicyAuditHistory(
            UUID.randomUUID(),
            id,
            prevVersion,
            newVersion,
            username,
            "UPDATE_POLICY",
            req.changeReason(),
            Instant.now()
        );
        policyRepository.savePolicyAuditHistory(audit);

        return ResponseEntity.ok(SecurityPolicyResponse.from(updated));
    }

    @GetMapping("/policies/{id}/history")
    public ResponseEntity<List<PolicyAuditHistory>> getPolicyAuditHistory(@PathVariable("id") String id) {
        return ResponseEntity.ok(policyRepository.findAuditHistoryByPolicyId(id));
    }

    // =========================================================================
    // 2. Policy Decision Endpoints (/adaptive-decisions)
    // =========================================================================

    @GetMapping("/adaptive-decisions")
    public ResponseEntity<PolicyDecisionPageResponse> getDecisions(
        @RequestParam(name = "page", defaultValue = "0") int page,
        @RequestParam(name = "size", defaultValue = "20") int size,
        @RequestParam(name = "status", required = false) String statusStr,
        @RequestParam(name = "category", required = false) String categoryStr,
        @RequestParam(name = "search", required = false) String search
    ) {
        PolicyStatus status = statusStr != null && !statusStr.isBlank() ? PolicyStatus.valueOf(statusStr) : null;
        PolicyCategory category = categoryStr != null && !categoryStr.isBlank() ? PolicyCategory.valueOf(categoryStr) : null;

        List<AdaptivePolicyDecision> decisions = policyRepository.findDecisions(page, size, status, category, search);
        long total = policyRepository.countDecisions(status, category, search);
        int totalPages = (int) Math.ceil((double) total / Math.max(1, size));

        List<AdaptivePolicyDecisionResponse> content = decisions.stream()
            .map(AdaptivePolicyDecisionResponse::from)
            .toList();

        return ResponseEntity.ok(new PolicyDecisionPageResponse(content, total, totalPages, page, size));
    }

    @GetMapping("/adaptive-decisions/{id}")
    public ResponseEntity<AdaptivePolicyDecisionResponse> getDecisionById(@PathVariable("id") UUID id) {
        AdaptivePolicyDecision decision = policyRepository.findDecisionById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy decision not found: " + id));
        return ResponseEntity.ok(AdaptivePolicyDecisionResponse.from(decision));
    }

    @GetMapping("/adaptive-decisions/{id}/actions")
    public ResponseEntity<List<PolicyDecisionAction>> getDecisionActions(@PathVariable("id") UUID id) {
        return ResponseEntity.ok(policyRepository.findActionsByDecisionId(id));
    }

    @PostMapping("/adaptive-decisions/{id}/approve")
    public ResponseEntity<AdaptivePolicyDecisionResponse> approveDecision(
        @PathVariable("id") UUID id,
        @Valid @RequestBody(required = false) PolicyApprovalRequest req
    ) {
        AdaptivePolicyDecision decision = policyRepository.findDecisionById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy decision not found: " + id));

        String username = resolveCurrentUsername();
        String comment = req != null && req.comment() != null ? req.comment() : "Recommendation approved by analyst.";

        policyRepository.updateDecisionStatus(id, PolicyStatus.APPROVED, username, "APPROVED", comment);

        PolicyDecisionAction action = new PolicyDecisionAction(
            UUID.randomUUID(),
            id,
            "APPROVED",
            username,
            comment,
            Instant.now()
        );
        policyRepository.saveDecisionAction(action);

        return ResponseEntity.ok(AdaptivePolicyDecisionResponse.from(
            policyRepository.findDecisionById(id).orElse(decision)
        ));
    }

    @PostMapping("/adaptive-decisions/{id}/reject")
    public ResponseEntity<AdaptivePolicyDecisionResponse> rejectDecision(
        @PathVariable("id") UUID id,
        @Valid @RequestBody PolicyRejectionRequest req
    ) {
        AdaptivePolicyDecision decision = policyRepository.findDecisionById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy decision not found: " + id));

        String username = resolveCurrentUsername();

        policyRepository.updateDecisionStatus(id, PolicyStatus.REJECTED, username, "REJECTED", req.rationale());

        PolicyDecisionAction action = new PolicyDecisionAction(
            UUID.randomUUID(),
            id,
            "REJECTED",
            username,
            req.rationale(),
            Instant.now()
        );
        policyRepository.saveDecisionAction(action);

        return ResponseEntity.ok(AdaptivePolicyDecisionResponse.from(
            policyRepository.findDecisionById(id).orElse(decision)
        ));
    }

    @PostMapping("/adaptive-decisions/evaluate/incident/{incidentId}")
    public ResponseEntity<AdaptivePolicyDecisionResponse> evaluateIncident(@PathVariable("incidentId") UUID incidentId) {
        SecurityIncident incident = incidentRepository.findById(incidentId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found: " + incidentId));

        List<DetectionEvidence> evidence = incidentRepository.findEvidenceByIncidentId(incidentId);
        AdaptivePolicyDecision decision = policyEngine.evaluateIncident(incident, evidence);
        return ResponseEntity.ok(AdaptivePolicyDecisionResponse.from(decision));
    }

    @PostMapping("/adaptive-decisions/evaluate/campaign/{campaignId}")
    public ResponseEntity<AdaptivePolicyDecisionResponse> evaluateCampaign(@PathVariable("campaignId") UUID campaignId) {
        ExfiltrationCampaign campaign = campaignRepository.findById(campaignId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign not found: " + campaignId));

        AdaptivePolicyDecision decision = policyEngine.evaluateCampaign(campaign, Collections.emptyList(), null);
        return ResponseEntity.ok(AdaptivePolicyDecisionResponse.from(decision));
    }

    private String resolveCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getName() != null && !auth.getName().isBlank())
            ? auth.getName()
            : "analyst-system";
    }
}
