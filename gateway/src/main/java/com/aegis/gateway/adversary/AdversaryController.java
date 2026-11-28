package com.aegis.gateway.adversary;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST API exposing Automated AI Adversary (Red Team) campaigns and
 * Self-Healing Policy Synthesizer (Blue Team) lifecycle management.
 */
@RestController
@RequestMapping("/api/v1/security/adversary")
public class AdversaryController {

    private final AdversaryCampaignService campaignService;
    private final PolicySynthesizerService synthesizerService;

    @Autowired
    public AdversaryController(
            AdversaryCampaignService campaignService,
            PolicySynthesizerService synthesizerService) {
        this.campaignService = campaignService;
        this.synthesizerService = synthesizerService;
    }

    // ------------------------------------------------------------------------
    // AI Adversary Campaigns (Red Team)
    // ------------------------------------------------------------------------

    @GetMapping("/campaigns")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<AdversaryCampaign>> getCampaigns() {
        return ResponseEntity.ok(campaignService.getCampaigns());
    }

    @GetMapping("/campaigns/{id}")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<AdversaryCampaign> getCampaign(@PathVariable String id) {
        Optional<AdversaryCampaign> campaign = campaignService.getCampaign(id);
        return campaign.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record RunCampaignRequest(String name, String targetEndpoint, AdversaryMutationStrategy strategy, Integer probeCount) {}

    @PostMapping("/campaigns/run")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<AdversaryCampaign> runCampaign(@RequestBody RunCampaignRequest request) {
        AdversaryMutationStrategy strategy = request.strategy() != null ? request.strategy() : AdversaryMutationStrategy.STEP_SKIPPING;
        int probes = request.probeCount() != null ? request.probeCount() : 15;
        AdversaryCampaign campaign = campaignService.runCampaign(request.name(), request.targetEndpoint(), strategy, probes);
        return ResponseEntity.status(HttpStatus.CREATED).body(campaign);
    }

    // ------------------------------------------------------------------------
    // Self-Healing Policy Synthesizer (Blue Team)
    // ------------------------------------------------------------------------

    @GetMapping("/synthesizer/candidates")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<CandidatePolicy>> getCandidates() {
        return ResponseEntity.ok(synthesizerService.getCandidates());
    }

    public record SynthesizeRequest(String campaignId) {}

    @PostMapping("/synthesizer/synthesize")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<CandidatePolicy> synthesizePolicy(@RequestBody SynthesizeRequest request) {
        CandidatePolicy candidate = synthesizerService.synthesizeFromCampaign(request.campaignId());
        return ResponseEntity.status(HttpStatus.CREATED).body(candidate);
    }

    public record ShadowEvaluationRequest(Integer shadowBatchSize) {}

    @PostMapping("/synthesizer/evaluate/{id}")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<CandidatePolicy> evaluateShadowFpr(
            @PathVariable String id,
            @RequestBody(required = false) ShadowEvaluationRequest request) {
        int batchSize = (request != null && request.shadowBatchSize() != null) ? request.shadowBatchSize() : 20;
        CandidatePolicy evaluated = synthesizerService.evaluateShadowMode(id, batchSize);
        return ResponseEntity.ok(evaluated);
    }

    @PostMapping("/synthesizer/promote/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<CandidatePolicy> promoteCandidate(@PathVariable String id) {
        CandidatePolicy promoted = synthesizerService.promoteCandidate(id);
        return ResponseEntity.ok(promoted);
    }
}
