package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;
import com.aegis.gateway.detection.campaign.CampaignRepository;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.policy.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class PolicyControllerTest {

    private PolicyRepository policyRepository;
    private AdaptivePolicyEngine policyEngine;
    private IncidentRepository incidentRepository;
    private CampaignRepository campaignRepository;
    private PolicyController controller;

    private final UUID decisionId = UUID.randomUUID();
    private AdaptivePolicyDecision sampleDecision;
    private SecurityPolicy samplePolicy;

    @BeforeEach
    void setUp() {
        policyRepository = mock(PolicyRepository.class);
        policyEngine = mock(AdaptivePolicyEngine.class);
        incidentRepository = mock(IncidentRepository.class);
        campaignRepository = mock(CampaignRepository.class);

        controller = new PolicyController(
            policyRepository, policyEngine, incidentRepository, campaignRepository
        );

        samplePolicy = new SecurityPolicy(
            "POL-BOLA-CONFIRMED-01",
            "Confirmed BOLA Escalation Policy",
            "1.0.0",
            PolicyCategory.AUTHORIZATION,
            PolicyAction.ESCALATE_INCIDENT,
            "Recommends escalation on confirmed cross-owner leakage",
            true,
            85.0,
            "200 on cross-owner resource",
            Instant.now(),
            Instant.now()
        );

        sampleDecision = new AdaptivePolicyDecision(
            decisionId,
            UUID.randomUUID(),
            null,
            "POL-BOLA-CONFIRMED-01",
            "1.0.0",
            PolicyCategory.AUTHORIZATION,
            "CRITICAL",
            PolicyAction.ESCALATE_INCIDENT,
            "ADVISORY",
            "Confirmed cross-owner resource exfiltration detected.",
            List.of("Incident:inc-1", "Rule:RULE-BOLA-CONFIRMED-01"),
            "cust-victim-1",
            "tenant-default",
            CampaignEvidenceCompleteness.COMPLETE,
            "{\"incidentId\":\"inc-1\"}",
            PolicyStatus.RECOMMENDED,
            null,
            null,
            null,
            null,
            Instant.now(),
            Instant.now().plusSeconds(86400 * 7),
            Instant.now()
        );
    }

    @Test
    @DisplayName("GET /policies returns all active security policies")
    void getAllPolicies() {
        when(policyRepository.findAllPolicies()).thenReturn(List.of(samplePolicy));

        ResponseEntity<List<SecurityPolicyResponse>> resp = controller.getAllPolicies();

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).hasSize(1);
        assertThat(resp.getBody().get(0).id()).isEqualTo("POL-BOLA-CONFIRMED-01");
        assertThat(resp.getBody().get(0).recommendedAction()).isEqualTo(PolicyAction.ESCALATE_INCIDENT);
    }

    @Test
    @DisplayName("PUT /policies/{id} updates policy configuration, bumps version, and records audit trail")
    void updatePolicyConfiguration() {
        when(policyRepository.findPolicyById("POL-BOLA-CONFIRMED-01")).thenReturn(Optional.of(samplePolicy));

        PolicyUpdateRequest req = new PolicyUpdateRequest(
            true, 90.0, "Tuned risk threshold for high-assurance environment", "Periodic SOC threshold review"
        );

        ResponseEntity<SecurityPolicyResponse> resp = controller.updatePolicy("POL-BOLA-CONFIRMED-01", req);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody().version()).isEqualTo("1.1.0");
        assertThat(resp.getBody().riskThreshold()).isEqualTo(90.0);

        verify(policyRepository).updatePolicy(any(SecurityPolicy.class));
        verify(policyRepository).savePolicyAuditHistory(any(PolicyAuditHistory.class));
    }

    @Test
    @DisplayName("GET /policy-decisions returns paginated decision recommendations")
    void getDecisionsPaginated() {
        when(policyRepository.findDecisions(0, 20, null, null, null)).thenReturn(List.of(sampleDecision));
        when(policyRepository.countDecisions(null, null, null)).thenReturn(1L);

        ResponseEntity<PolicyDecisionPageResponse> resp = controller.getDecisions(0, 20, null, null, null);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody().totalElements()).isEqualTo(1L);
        assertThat(resp.getBody().content().get(0).id()).isEqualTo(decisionId);
        assertThat(resp.getBody().content().get(0).recommendedAction()).isEqualTo(PolicyAction.ESCALATE_INCIDENT);
    }

    @Test
    @DisplayName("POST /policy-decisions/{id}/approve records analyst approval and updates status")
    void approveDecision() {
        when(policyRepository.findDecisionById(decisionId)).thenReturn(Optional.of(sampleDecision));

        PolicyApprovalRequest req = new PolicyApprovalRequest("Verified with data owner, proceeding with investigation.");
        ResponseEntity<AdaptivePolicyDecisionResponse> resp = controller.approveDecision(decisionId, req);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(policyRepository).updateDecisionStatus(eq(decisionId), eq(PolicyStatus.APPROVED), any(), eq("APPROVED"), eq(req.comment()));
        verify(policyRepository).saveDecisionAction(any(PolicyDecisionAction.class));
    }

    @Test
    @DisplayName("POST /policy-decisions/{id}/reject records analyst rejection with mandatory rationale")
    void rejectDecision() {
        when(policyRepository.findDecisionById(decisionId)).thenReturn(Optional.of(sampleDecision));

        PolicyRejectionRequest req = new PolicyRejectionRequest("Authorized maintenance script run by DevOps; expected cross-tenant query.");
        ResponseEntity<AdaptivePolicyDecisionResponse> resp = controller.rejectDecision(decisionId, req);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(policyRepository).updateDecisionStatus(eq(decisionId), eq(PolicyStatus.REJECTED), any(), eq("REJECTED"), eq(req.rationale()));
        verify(policyRepository).saveDecisionAction(any(PolicyDecisionAction.class));
    }

    @Test
    @DisplayName("GET /policy-decisions/{id} throws 404 if decision not found")
    void getDecisionNotFound() {
        UUID unknownId = UUID.randomUUID();
        when(policyRepository.findDecisionById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.getDecisionById(unknownId))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("404");
    }
}
