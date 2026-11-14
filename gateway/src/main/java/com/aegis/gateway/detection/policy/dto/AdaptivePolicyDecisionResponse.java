package com.aegis.gateway.detection.policy.dto;

import com.aegis.gateway.detection.policy.AdaptivePolicyDecision;
import com.aegis.gateway.detection.policy.PolicyAction;
import com.aegis.gateway.detection.policy.PolicyCategory;
import com.aegis.gateway.detection.policy.PolicyStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AdaptivePolicyDecisionResponse(
    UUID id,
    UUID incidentId,
    UUID campaignId,
    String policyId,
    String policyVersion,
    PolicyCategory category,
    String riskLevel,
    PolicyAction recommendedAction,
    String enforcementLevel,
    String rationale,
    List<String> supportingEvidence,
    String identityContext,
    String tenantId,
    String evidenceCompleteness,
    String evidenceSnapshot,
    PolicyStatus status,
    String analystUser,
    String analystAction,
    String analystRationale,
    Instant analystActionAt,
    Instant decidedAt,
    Instant expiresAt,
    Instant createdAt
) {
    public static AdaptivePolicyDecisionResponse from(AdaptivePolicyDecision d) {
        return new AdaptivePolicyDecisionResponse(
            d.id(),
            d.incidentId(),
            d.campaignId(),
            d.policyId(),
            d.policyVersion(),
            d.category(),
            d.riskLevel(),
            d.recommendedAction(),
            d.enforcementLevel(),
            d.rationale(),
            d.supportingEvidence(),
            d.identityContext(),
            d.tenantId(),
            d.evidenceCompleteness() != null ? d.evidenceCompleteness().name() : "COMPLETE",
            d.evidenceSnapshot(),
            d.status(),
            d.analystUser(),
            d.analystAction(),
            d.analystRationale(),
            d.analystActionAt(),
            d.decidedAt(),
            d.expiresAt(),
            d.createdAt()
        );
    }
}
