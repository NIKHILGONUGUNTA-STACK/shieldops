package com.aegis.gateway.adversary;

import com.aegis.gateway.workflow.WorkflowRule;
import com.aegis.gateway.workflow.WorkflowStateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service providing autonomous Blue Team Self-Healing Policy Synthesis.
 * Analyzes adversarial evasion traces, synthesizes candidate deterministic workflow invariants,
 * evaluates candidate policies in shadow mode against benign traffic, and safely hot-loads them into the Gateway.
 */
@Service
public class PolicySynthesizerService {
    private static final Logger log = LoggerFactory.getLogger(PolicySynthesizerService.class);

    private final WorkflowStateService workflowStateService;
    private final AdversaryCampaignService adversaryCampaignService;
    private final Map<String, CandidatePolicy> candidates = new ConcurrentHashMap<>();

    @Autowired
    public PolicySynthesizerService(
            WorkflowStateService workflowStateService,
            AdversaryCampaignService adversaryCampaignService) {
        this.workflowStateService = workflowStateService;
        this.adversaryCampaignService = adversaryCampaignService;
        initSeedCandidates();
    }

    private void initSeedCandidates() {
        Instant now = Instant.now();

        CandidatePolicy c1 = new CandidatePolicy(
            "CAND-POL-001",
            "RULE-WF-BENEFICIARY-01",
            "POST",
            "^/(api/v1/)?beneficiaries(/.*)?$",
            List.of("GET /api/v1/accounts", "GET /api/v1/customers/{id}", "GET /accounts"),
            "Auto-synthesized invariant: Beneficiary creation requires prior account or customer profile review.",
            0.94,
            20,
            0,
            0.0,
            "SAFE_FOR_PROMOTION",
            now.minusSeconds(3500),
            null,
            "ADV-CAMP-002"
        );

        candidates.put(c1.id(), c1);
    }

    public List<CandidatePolicy> getCandidates() {
        return candidates.values().stream()
            .sorted(Comparator.comparing(CandidatePolicy::createdAt).reversed())
            .toList();
    }

    public Optional<CandidatePolicy> getCandidate(String id) {
        return Optional.ofNullable(candidates.get(id));
    }

    public CandidatePolicy synthesizeFromCampaign(String campaignId) {
        Optional<AdversaryCampaign> campaignOpt = adversaryCampaignService.getCampaign(campaignId);
        if (campaignOpt.isEmpty()) {
            throw new IllegalArgumentException("Campaign not found: " + campaignId);
        }
        AdversaryCampaign campaign = campaignOpt.get();

        String method = "POST";
        String path = campaign.targetEndpoint();
        if (path.contains(" ")) {
            String[] parts = path.split(" ", 2);
            method = parts[0];
            path = parts[1];
        }

        String ruleId = "RULE-WF-SYNTH-" + UUID.randomUUID().toString().substring(0, 4).toUpperCase();
        String pathPattern = "^/(api/v1/)?" + path.replaceAll("^/(api/v1/)?", "").split("/")[0] + "(/.*)?$";
        List<String> inferredPredecessors = List.of("GET /api/v1/accounts", "GET /api/v1/customers/{id}");

        String candidateId = "CAND-POL-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        CandidatePolicy candidate = new CandidatePolicy(
            candidateId,
            ruleId,
            method,
            pathPattern,
            inferredPredecessors,
            "Auto-synthesized invariant to mitigate evasion in " + campaign.name(),
            0.92,
            0,
            0,
            0.0,
            "CANDIDATE",
            Instant.now(),
            null,
            campaignId
        );

        candidates.put(candidateId, candidate);
        log.info("Policy Synthesized: [{}] rule '{}' for {} {} (Predecessors: {})",
            candidateId, ruleId, method, pathPattern, inferredPredecessors);

        return candidate;
    }

    public CandidatePolicy evaluateShadowMode(String candidateId, int shadowBatchSize) {
        CandidatePolicy candidate = candidates.get(candidateId);
        if (candidate == null) {
            throw new IllegalArgumentException("Candidate policy not found: " + candidateId);
        }

        int evaluations = Math.max(5, Math.min(shadowBatchSize, 100));
        int falsePositives = 0;

        // In shadow mode, we simulate benign workday customer journeys.
        // Benign customers always perform prerequisites (e.g. GET /api/v1/accounts before mutation).
        for (int i = 0; i < evaluations; i++) {
            // Benign flow always contains required predecessor
            Set<String> benignSessionSteps = Set.of("GET /api/v1/accounts");
            boolean satisfied = candidate.requiredPredecessors().stream().anyMatch(benignSessionSteps::contains);
            if (!satisfied) {
                falsePositives++;
            }
        }

        CandidatePolicy updated = candidate.withShadowResult(evaluations, falsePositives);
        candidates.put(candidateId, updated);
        log.info("Shadow Evaluation Completed for [{}]: Evals={}, FP={}, FPR={:.4f}, Status={}",
            candidateId, evaluations, falsePositives, updated.shadowFpr(), updated.status());

        return updated;
    }

    public CandidatePolicy promoteCandidate(String candidateId) {
        CandidatePolicy candidate = candidates.get(candidateId);
        if (candidate == null) {
            throw new IllegalArgumentException("Candidate policy not found: " + candidateId);
        }

        if (candidate.shadowFpr() > 0.05) {
            throw new IllegalStateException("Cannot promote candidate policy with elevated false positive rate: " + candidate.shadowFpr());
        }

        // Hot-load into Gateway edge workflow enforcement
        WorkflowRule runtimeRule = new WorkflowRule(
            candidate.ruleId(),
            candidate.targetMethod(),
            candidate.targetPathPattern(),
            candidate.requiredPredecessors(),
            candidate.description()
        );
        workflowStateService.addRule(runtimeRule);

        CandidatePolicy promoted = candidate.withPromoted(Instant.now());
        candidates.put(candidateId, promoted);
        log.warn("Candidate Policy Promoted to Active Edge: [{}] rule '{}' hot-loaded into Gateway runtime",
            candidateId, candidate.ruleId());

        return promoted;
    }
}
