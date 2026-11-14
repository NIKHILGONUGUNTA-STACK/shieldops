package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Structured context-aware security policy recommendation.
 * Strictly non-enforcing (advisory-only).
 */
public record AdaptivePolicyDecision(
    UUID id,
    UUID incidentId,
    UUID campaignId,
    String policyId,
    String policyVersion,
    PolicyCategory category,
    String riskLevel,
    PolicyAction recommendedAction,
    String enforcementLevel, // "ADVISORY" strictly
    String rationale,
    List<String> supportingEvidence,
    String identityContext,
    String tenantId,
    CampaignEvidenceCompleteness evidenceCompleteness,
    String evidenceSnapshot,
    PolicyStatus status,
    String analystUser,
    String analystAction,
    String analystRationale,
    Instant analystActionAt,
    Instant decidedAt,
    Instant expiresAt,
    Instant createdAt
) {}
