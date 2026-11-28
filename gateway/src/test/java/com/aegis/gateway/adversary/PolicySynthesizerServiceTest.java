package com.aegis.gateway.adversary;

import com.aegis.gateway.workflow.WorkflowCheckResult;
import com.aegis.gateway.workflow.WorkflowStateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicySynthesizerServiceTest {

    private WorkflowStateService workflowStateService;
    private AdversaryCampaignService adversaryCampaignService;
    private PolicySynthesizerService synthesizerService;

    @BeforeEach
    void setUp() {
        workflowStateService = new WorkflowStateService(null);
        adversaryCampaignService = new AdversaryCampaignService(workflowStateService);
        synthesizerService = new PolicySynthesizerService(workflowStateService, adversaryCampaignService);
    }

    @Test
    @DisplayName("Should initialize with seeded candidate policy")
    void testSeedCandidates() {
        List<CandidatePolicy> candidates = synthesizerService.getCandidates();
        assertThat(candidates).hasSizeGreaterThanOrEqualTo(1);

        Optional<CandidatePolicy> c1 = synthesizerService.getCandidate("CAND-POL-001");
        assertThat(c1).isPresent();
        assertThat(c1.get().ruleId()).isEqualTo("RULE-WF-BENEFICIARY-01");
        assertThat(c1.get().status()).isEqualTo("SAFE_FOR_PROMOTION");
    }

    @Test
    @DisplayName("Synthesize candidate policy from campaign evasion")
    void testSynthesizeFromCampaign() {
        CandidatePolicy candidate = synthesizerService.synthesizeFromCampaign("ADV-CAMP-002");
        assertThat(candidate).isNotNull();
        assertThat(candidate.targetMethod()).isEqualTo("POST");
        assertThat(candidate.requiredPredecessors()).contains("GET /api/v1/accounts");
        assertThat(candidate.status()).isEqualTo("CANDIDATE");
    }

    @Test
    @DisplayName("Evaluate shadow FPR on candidate policy against simulated benign sessions")
    void testEvaluateShadowMode() {
        CandidatePolicy candidate = synthesizerService.synthesizeFromCampaign("ADV-CAMP-002");
        CandidatePolicy evaluated = synthesizerService.evaluateShadowMode(candidate.id(), 15);

        assertThat(evaluated.shadowEvaluationsCount()).isEqualTo(15);
        assertThat(evaluated.shadowFalsePositives()).isEqualTo(0);
        assertThat(evaluated.shadowFpr()).isEqualTo(0.0);
        assertThat(evaluated.status()).isEqualTo("SAFE_FOR_PROMOTION");
    }

    @Test
    @DisplayName("Promote candidate policy hot-loads rule into Gateway and blocks subsequent skipped steps")
    void testPromoteCandidatePolicy() {
        CandidatePolicy candidate = synthesizerService.getCandidate("CAND-POL-001").orElseThrow();

        // Before promotion: POST /api/v1/beneficiaries is unconstrained
        WorkflowCheckResult before = workflowStateService.checkCompliance(
            "sess-unpromoted",
            "POST",
            "/api/v1/beneficiaries",
            List.of("ROLE_CUSTOMER")
        );
        assertThat(before.allowed()).isTrue();

        // Promote candidate
        CandidatePolicy promoted = synthesizerService.promoteCandidate(candidate.id());
        assertThat(promoted.status()).isEqualTo("PROMOTED");
        assertThat(promoted.promotedAt()).isNotNull();

        // After promotion: POST /api/v1/beneficiaries is strictly blocked without predecessor!
        WorkflowCheckResult after = workflowStateService.checkCompliance(
            "sess-after-promoted",
            "POST",
            "/api/v1/beneficiaries",
            List.of("ROLE_CUSTOMER")
        );
        assertThat(after.allowed()).isFalse();
        assertThat(after.ruleId()).isEqualTo("RULE-WF-BENEFICIARY-01");
    }
}
